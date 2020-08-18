//! Revault scripts
//!
//! Get the output and script descriptors for policies specific to the Revault architecture.
//! We use [miniscript](http://bitcoin.sipa.be/miniscript/) in order to "safely" derive
//! scripts depending on the setup configuration (ie the number of overall participants and the
//! number of fund managers).
//!
//! Note these functions are not safe to reuse once the architecture set up, as the
//! returned descriptors are non-deterministically compiled from an abstract policy.

use super::error::RevaultError;

use bitcoin::PublicKey;
use miniscript::{policy::concrete::Policy, Descriptor, Segwitv0};

// FIXME: use extended pubkeys everywhere after https://github.com/rust-bitcoin/rust-miniscript/pull/116

/// Get the miniscript descriptor for the vault outputs.
///
/// The vault policy is an N-of-N, so `thresh(len(all_pubkeys), all_pubkeys)`.
///
/// # Examples
/// ```rust
/// use revault::scripts;
/// use bitcoin;
/// use secp256k1;
///
/// let secp = secp256k1::Secp256k1::new();
/// let secret_key = secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
/// let public_key = bitcoin::PublicKey {
///     compressed: true,
///     key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key),
/// };
/// let vault_descriptor =
///     scripts::default_vault_descriptor(&[public_key, public_key]).expect("Compiling descriptor");
///
/// println!("Vault descriptor redeem script: {}", vault_descriptor.witness_script());
/// ```
///
/// # Errors
/// - If the passed slice contains less than 2 public keys.
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
pub fn default_vault_descriptor(
    participants: &[PublicKey],
) -> Result<Descriptor<PublicKey>, RevaultError> {
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
        Ok(miniscript) => Ok(Descriptor::<PublicKey>::Wsh(miniscript)),
    }
}

/// Get the miniscript descriptors for the unvault outputs.
///
/// The unvault policy allows either all the participants together to spend, or (the fund managers
/// + the cosigners) after a timelock.
///
/// As the managers are part of the participants we can have a more efficient Script by expliciting
/// to the compiler that the spenders are always going to sign. Thus we end up with:
/// ```text
/// and(thresh(len(managers), spenders), or(thresh(len(non_managers), non_managers),
/// and(thresh(len(cosigners), cosigners), older(X))))
/// ````
///
/// As we expect the usual operations to be far more likely, we further optimize the policy to:
/// ```text
/// and(thresh(len(managers), managers), or(1@thresh(len(non_managers), non_managers),
/// 10@and(thresh(len(cosigners), cosigners), older(X))))
/// ```
///
/// # Examples
/// ```rust
/// use revault::scripts;
/// use bitcoin;
/// use secp256k1;
///
/// let secp = secp256k1::Secp256k1::new();
/// let secret_key = secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
/// let public_key = bitcoin::PublicKey {
///     compressed: true,
///     key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key),
/// };
/// let unvault_descriptor = scripts::default_unvault_descriptor(
///     // Non-managers
///     &[public_key, public_key, public_key],
///     // Managers
///     &[public_key, public_key],
///     // Cosigners
///     &[public_key, public_key, public_key],
///     // CSV
///     42
/// ).expect("Compiling descriptor");
///
/// println!("Unvault descriptor redeem script: {}", unvault_descriptor.witness_script());
/// ```
///
/// # Errors
/// - If any of the slice contains no public key, or if the number of non_managers public keys is
/// not the same as the number of cosigners public key.
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
pub fn default_unvault_descriptor(
    non_managers: &[PublicKey],
    managers: &[PublicKey],
    cosigners: &[PublicKey],
    csv_value: u32,
) -> Result<Descriptor<PublicKey>, RevaultError> {
    if non_managers.is_empty() || managers.is_empty() || cosigners.len() != non_managers.len() {
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

    let cosigners_and_csv = Policy::And(vec![cosigners_thres, Policy::After(csv_value)]);

    let cosigners_or_non_spenders =
        Policy::Or(vec![(10, cosigners_and_csv), (1, non_spenders_thres)]);

    let policy = Policy::And(vec![spenders_thres, cosigners_or_non_spenders]);

    // This handles the non-safe or malleable cases.
    match policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(RevaultError::ScriptCreation(format!(
            "Unvault policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok(Descriptor::<PublicKey>::Wsh(miniscript)),
    }
}

/// Get the miniscript descriptor for the unvault transaction CPFP output.
///
/// It's a basic N-of-N between the fund managers.
///
/// # Errors
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
pub fn unvault_cpfp_descriptor(
    managers: &[PublicKey],
) -> Result<Descriptor<PublicKey>, RevaultError> {
    let pubkeys = managers
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();

    let policy = Policy::Threshold(pubkeys.len(), pubkeys);

    // This handles the non-safe or malleable cases.
    match policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(RevaultError::ScriptCreation(format!(
            "Unvault CPFP policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok(Descriptor::<PublicKey>::Wsh(miniscript)),
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::{
        default_unvault_descriptor, default_vault_descriptor, unvault_cpfp_descriptor, RevaultError,
    };

    use bitcoin::PublicKey;

    fn get_random_pubkey() -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let mut rand_bytes = [0u8; 32];
        // Make rustc happy..
        let mut secret_key = Err(secp256k1::Error::InvalidSecretKey);

        while secret_key.is_err() {
            rand::thread_rng().fill_bytes(&mut rand_bytes);
            secret_key = secp256k1::SecretKey::from_slice(&rand_bytes);
        }

        PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key.unwrap()),
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

            default_unvault_descriptor(&non_managers, &managers, &cosigners, 18).expect(&format!(
                "Unvault descriptors creation error with ({}, {})",
                n_managers, n_non_managers
            ));
            default_vault_descriptor(
                &managers
                    .iter()
                    .chain(non_managers.iter())
                    .copied()
                    .collect::<Vec<PublicKey>>(),
            )
            .expect(&format!(
                "Vault descriptors creation error with ({}, {})",
                n_managers, n_non_managers
            ));
            unvault_cpfp_descriptor(&managers).expect(&format!(
                "Unvault CPFP descriptors creation error with ({}, {})",
                n_managers, n_non_managers
            ));
        }
    }

    #[test]
    fn test_configuration_limits() {
        assert_eq!(
            default_vault_descriptor(&vec![get_random_pubkey()]),
            Err(RevaultError::ScriptCreation(
                "Vault: bad parameters. We need more than one participant.".to_string()
            ))
        );

        assert_eq!(
            default_unvault_descriptor(
                &vec![get_random_pubkey()],
                &vec![get_random_pubkey()],
                &vec![get_random_pubkey(), get_random_pubkey()],
                6
            ),
            Err(RevaultError::ScriptCreation(
                "Unvault: bad parameters. There must be a non-zero \
                number of managers and non_managers, and as many cosigners as non_managers"
                    .to_string()
            ))
        );

        // Maximum N-of-N (+ 1)
        let participants = (0..68)
            .map(|_| get_random_pubkey())
            .collect::<Vec<PublicKey>>();
        assert_eq!(default_vault_descriptor(&participants), Err(RevaultError::ScriptCreation("Vault policy compilation error: Atleast one spending path has more op codes executed than MAX_OPS_PER_SCRIPT".to_string())));

        // Maximum non-managers for 2 managers (+ 1)
        let managers = (0..2)
            .map(|_| get_random_pubkey())
            .collect::<Vec<PublicKey>>();
        let non_managers = (0..21)
            .map(|_| get_random_pubkey())
            .collect::<Vec<PublicKey>>();
        let cosigners = (0..21)
            .map(|_| get_random_pubkey())
            .collect::<Vec<PublicKey>>();
        assert_eq!(default_unvault_descriptor(&non_managers, &managers, &cosigners, 32), Err(RevaultError::ScriptCreation("Unvault policy compilation error: Atleast one spending path has more op codes executed than MAX_OPS_PER_SCRIPT".to_string())));
    }

    // TODO: extensively test all possibilities before reaching the limit
}
