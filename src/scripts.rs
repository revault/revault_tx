///! Revault scripts
///!
///! Get the output and script descriptors for policies specific to the Revault architecture.
///! We use miniscript (http://bitcoin.sipa.be/miniscript/) in order to be able to "safely" derive
///! scripts depending on the setup configuration (ie the number of overall participants and the
///! number of fund managers).
///!
///! Note that these functions are not safe to reuse once the architecture set up, as the
///! returned descriptors are non-deterministically compiled from an abstract policy.
use super::revault_error::RevaultError;

use bitcoin::PublicKey;
use miniscript::{policy::concrete::Policy, Descriptor, Miniscript, Segwitv0};

// FIXME: use extended pubkeys everywhere after https://github.com/rust-bitcoin/rust-miniscript/pull/116

/// Get the output and redeem script descriptors for the vault outputs.
///
/// The vault policy is an N-of-N, so `thresh(len(all_pubkeys), all_pubkeys)`.
pub fn get_default_vault_descriptors(
    participants: &Vec<PublicKey>,
) -> Result<(Descriptor<PublicKey>, Miniscript<PublicKey, Segwitv0>), RevaultError> {
    if participants.len() < 2 {
        return Err(RevaultError::ScriptCreation(
            "Vault: bad parameters. We need more than one participant.".to_string(),
        ));
    }

    let pubkeys = participants
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();

    // Note that this will be more optimal once
    // https://github.com/rust-bitcoin/rust-miniscript/pull/113 is merged
    let policy = Policy::Threshold(pubkeys.len(), pubkeys);

    // This handles the non-safe or malleable cases.
    match policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(RevaultError::ScriptCreation(format!(
            "Vault policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok((Descriptor::<PublicKey>::Wsh(miniscript.clone()), miniscript)),
    }
}

/// Get the output and redeem script descriptors for the unvault outputs.
///
/// The unvault policy allows either all the participants together to spend, or (the fund managers
/// + the cosigners) after a timelock.
/// As the managers are part of the participants we can have a more efficient Script by expliciting
/// to the compiler that the spenders are always going to sign.
///
/// Thus we end up with:
/// `and(thresh(len(managers), spenders), or(thresh(len(non_managers), non_managers),
/// and(thresh(len(cosigners), cosigners), older(X))))`
///
/// As we expect the usual operations to be far more likely, we further optimize the policy to:
/// `and(thresh(len(managers), managers), or(1@thresh(len(non_managers), non_managers),
/// 9@and(thresh(len(cosigners), cosigners), older(X))))`
pub fn get_default_unvault_descriptors(
    non_managers: &Vec<PublicKey>,
    managers: &Vec<PublicKey>,
    cosigners: &Vec<PublicKey>,
    csv_value: u32,
) -> Result<(Descriptor<PublicKey>, Miniscript<PublicKey, Segwitv0>), RevaultError> {
    if non_managers.len() < 1 || managers.len() < 1 || cosigners.len() != non_managers.len() {
        return Err(RevaultError::ScriptCreation(
            "Unvault: bad parameters. There must be a non-zero \
                number of managers and non_managers, and as many cosigners as non_managers"
                .to_string(),
        ));
    }

    let mut pubkeys = managers
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();
    let spenders_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    pubkeys = non_managers
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();
    let non_spenders_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    pubkeys = cosigners
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();
    let cosigners_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    let cosigners_and_csv = Policy::And(vec![cosigners_thres, Policy::Older(csv_value)]);

    let cosigners_or_non_spenders =
        Policy::Or(vec![(9, cosigners_and_csv), (1, non_spenders_thres)]);

    let policy = Policy::And(vec![spenders_thres, cosigners_or_non_spenders]);

    // This handles the non-safe or malleable cases.
    match policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(RevaultError::ScriptCreation(format!(
            "Vault policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok((Descriptor::<PublicKey>::Wsh(miniscript.clone()), miniscript)),
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::{get_default_unvault_descriptors, get_default_vault_descriptors};

    use bitcoin::PublicKey;

    fn get_random_pubkey() -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let mut rand_bytes = [0u8; 32];

        rand::thread_rng().fill_bytes(&mut rand_bytes);
        let secret_key = secp256k1::SecretKey::from_slice(&rand_bytes).expect("curve order");

        PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key),
        }
    }

    #[test]
    fn test_possible_default_configurations() {
        // Policy compilation takes time, so just test some remarkable ones
        let configurations = [
            // Single-manager configurations
            (1, 1),
            (1, 2),
            (1, 5),
            // Multiple-manager configurations
            (2, 3),
            (4, 2),
            (7, 1),
            (3, 8),
            // Huge configurations
            (15, 5),
            (25, 5),
            (7, 13),
            (8, 12),
            (3, 18),
        ];

        for (n_managers, n_non_managers) in configurations.iter() {
            let managers = (0..*n_managers)
                .map(|_| get_random_pubkey())
                .collect::<Vec<PublicKey>>();
            let non_managers = (0..*n_non_managers)
                .map(|_| get_random_pubkey())
                .collect::<Vec<PublicKey>>();
            let cosigners = (0..*n_non_managers)
                .map(|_| get_random_pubkey())
                .collect::<Vec<PublicKey>>();

            get_default_unvault_descriptors(&non_managers, &managers, &cosigners, 18).expect(
                &format!(
                    "Unvault descriptors creation error with ({}, {})",
                    n_managers, n_non_managers
                ),
            );
            get_default_vault_descriptors(
                &managers
                    .into_iter()
                    .chain(non_managers.into_iter())
                    .collect(),
            )
            .expect(&format!(
                "Vault descriptors creation error with ({}, {})",
                n_managers, n_non_managers
            ));
        }
    }
}
