//! # Revault scripts
//!
//! Miniscript descriptors for policies specific to the Revault architecture.
//!
//! We use [miniscript](http://bitcoin.sipa.be/miniscript/) in order to "safely" derive
//! scripts depending on the setup configuration (ie the number of stakeholders, the
//! number of fund managers, and the relative timelock).
//!
//! Note these functions are not safe to reuse after initial set up, as the returned descriptors
//! are non-deterministically compiled from an abstract policy.
//! Backup the output Miniscript descriptors instead.

use crate::Error;

use bitcoin::util::bip32;
use miniscript::{
    descriptor::DescriptorPublicKey, policy::concrete::Policy, Descriptor, MiniscriptKey, Segwitv0,
};

// These are useful to create TxOuts out of the right Script descriptor

macro_rules! impl_descriptor_newtype {
    ($struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $struct_name<Pk: MiniscriptKey>(pub Descriptor<Pk>);

        impl $struct_name<DescriptorPublicKey> {
            /// Derives all wildcard keys in the descriptor using the supplied `child_number`
            pub fn derive(
                &self,
                child_number: bip32::ChildNumber,
            ) -> $struct_name<DescriptorPublicKey> {
                $struct_name(self.0.derive(child_number))
            }
        }
    };
}

impl_descriptor_newtype!(
    VaultDescriptor,
    doc = "The vault / deposit miniscript descriptor. See the [vault_descriptor] function for more information."
);

impl_descriptor_newtype!(
    UnvaultDescriptor,
    doc = "The unvault miniscript descriptor. See the [unvault_descriptor] function for more information."
);

impl_descriptor_newtype!(
    CpfpDescriptor,
    doc =
        "The CPFP miniscript descriptor. See the [cpfp_descriptor] function for more information."
);

/// Get the miniscript descriptor for the vault outputs.
///
/// The vault policy is an N-of-N, so `thresh(len(all_pubkeys), all_pubkeys)`.
///
/// # Examples
/// ```rust
/// use revault_tx::scripts;
/// use bitcoin;
/// use bitcoin::secp256k1;
///
/// let secp = secp256k1::Secp256k1::new();
/// let secret_key = secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
/// let public_key = bitcoin::PublicKey {
///     compressed: true,
///     key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key),
/// };
/// let vault_descriptor =
///     scripts::vault_descriptor(vec![public_key, public_key]).expect("Compiling descriptor");
///
/// println!("Vault descriptor redeem script: {}", vault_descriptor.0.witness_script());
/// ```
///
/// # Errors
/// - If the passed slice contains less than 2 public keys.
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
pub fn vault_descriptor<Pk: MiniscriptKey>(
    participants: Vec<Pk>,
) -> Result<VaultDescriptor<Pk>, Error> {
    if participants.len() < 2 {
        return Err(Error::ScriptCreation(
            "Vault: bad parameters. We need more than one participant.".to_string(),
        ));
    }

    let pubkeys = participants
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();

    let policy = Policy::Threshold(pubkeys.len(), pubkeys);

    // This handles the non-safe or malleable cases.
    match policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(Error::ScriptCreation(format!(
            "Vault policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok(VaultDescriptor(Descriptor::<Pk>::Wsh(miniscript))),
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
/// use revault_tx::scripts;
/// use bitcoin;
/// use bitcoin::secp256k1;
///
/// let secp = secp256k1::Secp256k1::new();
/// let secret_key = secp256k1::SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
/// let public_key = bitcoin::PublicKey {
///     compressed: true,
///     key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key),
/// };
/// let unvault_descriptor = scripts::unvault_descriptor(
///     // Stakeholders
///     vec![public_key, public_key, public_key],
///     // Managers
///     vec![public_key, public_key],
///     2,
///     // Cosigners
///     vec![public_key, public_key, public_key],
///     // CSV
///     42
/// ).expect("Compiling descriptor");
///
/// println!("Unvault descriptor redeem script: {}", unvault_descriptor.0.witness_script());
/// ```
///
/// # Errors
/// - If any of the slice contains no public key, or if the number of non_managers public keys is
/// not the same as the number of cosigners public key.
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
pub fn unvault_descriptor<Pk: MiniscriptKey>(
    stakeholders: Vec<Pk>,
    managers: Vec<Pk>,
    managers_threshold: usize,
    cosigners: Vec<Pk>,
    csv_value: u32,
) -> Result<UnvaultDescriptor<Pk>, Error> {
    if stakeholders.is_empty() || managers.is_empty() || cosigners.len() != stakeholders.len() {
        return Err(Error::ScriptCreation(
            "Unvault: bad parameters. There must be a non-zero \
                number of managers and non_managers, and as many cosigners as non_managers"
                .to_string(),
        ));
    }

    if managers_threshold > managers.len() {
        return Err(Error::ScriptCreation(
            "Unvault: bad parameters. The managers threshold is higher than \
                the number of managers."
                .to_owned(),
        ));
    }

    if (csv_value & (1 << 22)) != 0 {
        return Err(Error::ScriptCreation(
            "Unvault: bad parameters. The CSV must be specified in block granularity".to_owned(),
        ));
    }

    let mut pubkeys = managers
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();
    let spenders_thres = Policy::Threshold(managers_threshold, pubkeys);

    pubkeys = stakeholders
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();
    let stakeholders_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    pubkeys = cosigners
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();
    let cosigners_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    let cosigners_and_csv = Policy::And(vec![cosigners_thres, Policy::Older(csv_value)]);

    let managers_and_cosigners_and_csv = Policy::And(vec![spenders_thres, cosigners_and_csv]);

    let policy = Policy::Or(vec![
        (1, stakeholders_thres),
        (9, managers_and_cosigners_and_csv),
    ]);

    // This handles the non-safe or malleable cases.
    match policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(Error::ScriptCreation(format!(
            "Unvault policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok(UnvaultDescriptor(Descriptor::<Pk>::Wsh(miniscript))),
    }
}

/// Generates an unvault script descriptor with more control over each set of participants.
///
/// == A boilerplate "prefer not using this" warning goes here.. ==
/// The default [unvault_descriptor] is a safe(r) alternative.
///
/// This basically abstracts the policy and does a `or(stakeholders, and(managers, cosigners, CSV))`
/// in order to allow experiments with the set of keys of the managers not being included in
/// the set of keys of all the participants (does not necessarily means that the managers
/// *themselves* aren't part of this set).
/// Furthermore, this allows to custom the threshold values of each sub-policy as well as the
/// likelyhood of each branch of the or().
///
/// # Errors
/// - If any of the slice contains no public key, or if the number of non_managers public keys is
/// not the same as the number of cosigners public key.
/// - If the policy compilation to miniscript failed
#[allow(clippy::too_many_arguments)]
pub fn raw_unvault_descriptor<Pk: MiniscriptKey>(
    stakeholders_pubkeys: Vec<Pk>,
    stakeholders_thresh: usize,
    stakeholders_likelyhood: usize,
    managers_pubkeys: Vec<Pk>,
    managers_thresh: usize,
    cosigners_pubkeys: Vec<Pk>,
    cosigners_thresh: usize,
    csv_value: u32,
    managers_alone_likelyhood: usize,
) -> Result<Descriptor<Pk>, Error> {
    let stakeholders_pubkeys = stakeholders_pubkeys
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();
    let stakeholders = Policy::Threshold(stakeholders_thresh, stakeholders_pubkeys);

    let managers_pubkeys = managers_pubkeys
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();
    let managers = Policy::Threshold(managers_thresh, managers_pubkeys);

    let cosigners_pubkeys = cosigners_pubkeys
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();
    let cosigners = Policy::Threshold(cosigners_thresh, cosigners_pubkeys);

    let managers_alone = Policy::And(vec![
        managers,
        Policy::And(vec![cosigners, Policy::Older(csv_value)]),
    ]);

    let final_policy = Policy::Or(vec![
        (stakeholders_likelyhood, stakeholders),
        (managers_alone_likelyhood, managers_alone),
    ]);

    match final_policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(Error::ScriptCreation(format!(
            "Raw unvault policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok(Descriptor::<Pk>::Wsh(miniscript)),
    }
}

/// Get the miniscript descriptor for the CPFP outputs (used by managers for opportunistic
/// fee-bumping).
///
/// It's a basic N-of-N between the fund managers.
///
/// # Errors
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
pub fn cpfp_descriptor<Pk: MiniscriptKey>(managers: Vec<Pk>) -> Result<CpfpDescriptor<Pk>, Error> {
    let pubkeys = managers
        .into_iter()
        .map(Policy::Key)
        .collect::<Vec<Policy<Pk>>>();

    let policy = Policy::Threshold(1, pubkeys);

    // This handles the non-safe or malleable cases.
    match policy.compile::<Segwitv0>() {
        Err(compile_err) => Err(Error::ScriptCreation(format!(
            "CPFP policy compilation error: {}",
            compile_err
        ))),
        Ok(miniscript) => Ok(CpfpDescriptor(Descriptor::<Pk>::Wsh(miniscript))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cpfp_descriptor, raw_unvault_descriptor, unvault_descriptor, vault_descriptor, Error,
    };

    use bitcoin::{
        secp256k1::rand::{rngs::SmallRng, FromEntropy},
        PublicKey,
    };

    fn get_random_pubkey(rng: &mut SmallRng) -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(rng);

        PublicKey {
            compressed: true,
            key: public_key,
        }
    }

    #[test]
    fn test_possible_default_configurations() {
        // Policy compilation takes time, so just test some remarkable ones
        let configurations = [
            // Single-manager configurations
            ((1, 1), 1),
            ((1, 1), 2),
            ((1, 1), 5),
            // Multiple-manager configurations (with threshold)
            ((2, 2), 3),
            ((3, 4), 2),
            ((7, 7), 1),
            ((2, 3), 8),
            // Huge configurations
            ((15, 15), 5),
            ((20, 20), 5),
            ((7, 7), 13),
            ((8, 8), 12),
            ((3, 3), 18),
        ];

        let mut rng = SmallRng::from_entropy();
        for ((thresh, n_managers), n_stakeholders) in configurations.iter() {
            let managers = (0..*n_managers)
                .map(|_| get_random_pubkey(&mut rng))
                .collect::<Vec<PublicKey>>();
            let stakeholders = (0..*n_stakeholders)
                .map(|_| get_random_pubkey(&mut rng))
                .collect::<Vec<PublicKey>>();
            let cosigners = (0..*n_stakeholders)
                .map(|_| get_random_pubkey(&mut rng))
                .collect::<Vec<PublicKey>>();

            unvault_descriptor(
                stakeholders.clone(),
                managers.clone(),
                *thresh,
                cosigners.clone(),
                18,
            )
            .expect(&format!(
                "Unvault descriptors creation error with ({}, {})",
                n_managers, n_stakeholders
            ));
            vault_descriptor(
                managers
                    .clone()
                    .iter()
                    .chain(stakeholders.iter())
                    .copied()
                    .collect::<Vec<PublicKey>>(),
            )
            .expect(&format!(
                "Vault descriptors creation error with ({}, {})",
                n_managers, n_stakeholders
            ));
            cpfp_descriptor(managers).expect(&format!(
                "CPFP descriptors creation error with ({}, {})",
                n_managers, n_stakeholders
            ));
        }
    }

    #[test]
    fn test_default_configuration_limits() {
        let mut rng = SmallRng::from_entropy();

        assert_eq!(
            vault_descriptor(vec![get_random_pubkey(&mut rng)]),
            Err(Error::ScriptCreation(
                "Vault: bad parameters. We need more than one participant.".to_string()
            ))
        );

        assert_eq!(
            unvault_descriptor(
                vec![get_random_pubkey(&mut rng)],
                vec![get_random_pubkey(&mut rng)],
                1,
                vec![get_random_pubkey(&mut rng), get_random_pubkey(&mut rng)],
                6
            ),
            Err(Error::ScriptCreation(
                "Unvault: bad parameters. There must be a non-zero \
                number of managers and non_managers, and as many cosigners as non_managers"
                    .to_string()
            ))
        );

        assert_eq!(
            unvault_descriptor(
                vec![get_random_pubkey(&mut rng)],
                vec![get_random_pubkey(&mut rng)],
                1,
                vec![get_random_pubkey(&mut rng)],
                4194305
            ),
            Err(Error::ScriptCreation(
                "Unvault: bad parameters. The CSV must be specified in block granularity"
                    .to_owned()
            ))
        );

        assert_eq!(
            unvault_descriptor(
                vec![get_random_pubkey(&mut rng)],
                vec![get_random_pubkey(&mut rng)],
                2,
                vec![get_random_pubkey(&mut rng)],
                4194305
            ),
            Err(Error::ScriptCreation(
                "Unvault: bad parameters. The managers threshold is higher than the number of managers."
                    .to_owned()
            ))
        );

        // TODO: fix upstream, this should fail to compile (cf https://github.com/rust-bitcoin/rust-miniscript/issues/132)

        // Maximum N-of-N
        let participants = (0..67)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        vault_descriptor(participants).expect("Should be OK: max allowed value");
        // Now hit the limit
        //let participants = (0..68)
        //.map(|_| get_random_pubkey(&mut rng))
        //.collect::<Vec<PublicKey>>();
        //assert_eq!(vault_descriptor(&participants), Err(Error::ScriptCreation("Vault policy compilation error: Atleast one spending path has more op codes executed than MAX_OPS_PER_SCRIPT".to_string())));

        // Maximum 1-of-N
        let managers = (0..20)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        cpfp_descriptor(managers).expect("Should be OK, that's the maximum allowed value");
        // Hit the limit
        //let managers = (0..21)
        //.map(|_| get_random_pubkey(&mut rng))
        //.collect::<Vec<PublicKey>>();
        //assert_eq!(cpfp_descriptor(&managers), Err(Error::ScriptCreation("CPFP policy compilation error: Atleast one spending path has more op codes executed than MAX_OPS_PER_SCRIPT".to_string())));

        // Maximum non-managers for 2 managers
        let stakeholders = (0..38)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        let managers = (0..2)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        let cosigners = (0..38)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        unvault_descriptor(stakeholders, managers, 2, cosigners, 145).unwrap();

        // Now hit the limit
        let stakeholders = (0..39)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        let managers = (0..2)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        let cosigners = (0..39)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        assert_eq!(
            unvault_descriptor(stakeholders, managers, 2, cosigners, 32),
            Err(Error::ScriptCreation(
                "Unvault policy compilation error: Atleast one spending path \
                    has more op codes executed than MAX_OPS_PER_SCRIPT"
                    .to_string()
            ))
        );
    }

    #[test]
    pub fn test_raw_unvault_descriptor() {
        let mut rng = SmallRng::from_entropy();
        const CSV_VALUE: u32 = 33;

        let stakeholders = (0..5)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        let managers = (0..3)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        let all_participants = managers
            .iter()
            .chain(stakeholders.iter())
            .cloned()
            .collect::<Vec<PublicKey>>();

        let cosigners = (0..5)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();

        // We can reproduce the default policy
        let default_policy = raw_unvault_descriptor(
            all_participants.clone(),
            all_participants.len(),
            1,
            managers.clone(),
            managers.len(),
            cosigners.clone(),
            cosigners.len(),
            CSV_VALUE,
            10,
        )
        .expect("Default policy");
        // However it'll not be as optimized as the default constructor!
        // Note: doing this mainly to check if rust-miniscript will optimize this one day
        assert!(
            default_policy
                != unvault_descriptor(
                    stakeholders.clone(),
                    managers.clone(),
                    managers.len(),
                    cosigners.clone(),
                    CSV_VALUE
                )
                .unwrap()
                .0
        );

        // But that's obviously a huge footgun:
        raw_unvault_descriptor(
            managers.clone(),
            managers.len(),
            1,
            all_participants.clone(),
            all_participants.len(),
            cosigners.clone(),
            cosigners.len(),
            CSV_VALUE,
            10,
        )
        .expect("If arguments are reversed");

        // What's cool however is that we can now separate our sets:
        raw_unvault_descriptor(
            stakeholders.clone(),
            stakeholders.len(),
            1,
            managers.clone(),
            managers.len(),
            cosigners.clone(),
            cosigners.len(),
            CSV_VALUE,
            10,
        )
        .expect("When managers are not part of the stakeholders");

        // Or have different thresholds for each
        let managers_second_keys = (0..3)
            .map(|_| get_random_pubkey(&mut rng))
            .collect::<Vec<PublicKey>>();
        raw_unvault_descriptor(
            all_participants.clone(),
            all_participants.len() - 2, // That's a 3-of-5
            3,                          // Because why not
            managers_second_keys.clone(),
            managers_second_keys.len() - 1, // That's a 2-of-3
            cosigners.clone(),
            cosigners.len(),
            CSV_VALUE,
            7,
        )
        .expect("When passing custom thresholds");

        // Or both
        raw_unvault_descriptor(
            stakeholders.clone(),
            stakeholders.len() - 1,
            8,
            managers.clone(),
            managers.len() - 2,
            cosigners.clone(),
            cosigners.len(),
            CSV_VALUE,
            2,
        )
        .expect("When passing custom thresholds and managers not stakeholders");

        // But YA footgun: the policy compiler itself
        // FIXME: Not ME, upstream! This should be a compiler error, see https://github.com/rust-bitcoin/rust-miniscript/issues/115#issuecomment-674521015
        //raw_unvault_descriptor(
        //all_participants.clone(),
        //all_participants.len(),
        //1,
        //managers.clone(),
        //managers.len(),
        //cosigners.clone(),
        //cosigners.len(),
        //CSV_VALUE,
        //1,
        //)
        //.expect_err("Duplicated keys across paths");
    }
}
