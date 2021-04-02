//! # Revault scripts
//!
//! Miniscript descriptors for policies specific to the Revault architecture.
//!
//! We use [miniscript](http://bitcoin.sipa.be/miniscript/) in order to "safely" derive
//! scripts depending on the setup configuration (ie the number of stakeholders, the
//! number of fund managers, and the relative timelock) for all script but the (unknown Emergency
//! one).
//!
//! Note these functions are not safe to reuse after initial set up, as the returned descriptors
//! are non-deterministically compiled from an abstract policy.
//! Backup the output Miniscript descriptors instead.

use crate::error::*;

use miniscript::{
    bitcoin::{secp256k1, util::bip32, Address, PublicKey},
    descriptor::{DescriptorPublicKey, Wildcard},
    policy::concrete::Policy,
    Descriptor, ForEachKey, Segwitv0, TranslatePk2,
};

use std::fmt;

#[cfg(feature = "use-serde")]
use serde::de;

// These are useful to create TxOuts out of the right Script descriptor

macro_rules! impl_descriptor_newtype {
    ($struct_name:ident, $derived_struct_name:ident, $doc_comment:meta, $der_doc_comment:meta) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $struct_name(Descriptor<DescriptorPublicKey>);

        #[$der_doc_comment]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $derived_struct_name(Descriptor<PublicKey>);

        impl $struct_name {
            pub fn inner(&self) -> &Descriptor<DescriptorPublicKey> {
                &self.0
            }

            pub fn into_inner(self) -> Descriptor<DescriptorPublicKey> {
                self.0
            }

            /// Derives all wildcard keys in the descriptor using the supplied `child_number`
            pub fn derive<C: secp256k1::Verification>(
                &self,
                child_number: bip32::ChildNumber,
                secp: &secp256k1::Secp256k1<C>,
            ) -> $derived_struct_name {
                $derived_struct_name(
                    self.0
                        .derive(child_number.into())
                        .translate_pk2(|xpk| xpk.derive_public_key(secp))
                        .expect("All pubkeys are derived, no wildcard."),
                )
            }
        }

        impl $derived_struct_name {
            pub fn inner(&self) -> &Descriptor<PublicKey> {
                &self.0
            }

            pub fn into_inner(self) -> Descriptor<PublicKey> {
                self.0
            }
        }
    };
}

impl_descriptor_newtype!(
    DepositDescriptor,
    DerivedDepositDescriptor,
    doc = "A **generalistic** (with wildcard xpubs) vault / deposit miniscript descriptor. \
            See the [deposit_descriptor] function for more information.",
    doc = "A **concrete** (with raw public keys) vault / deposit miniscript descriptor. \
            See the [deposit_descriptor] function for more information."
);

impl_descriptor_newtype!(
    UnvaultDescriptor,
    DerivedUnvaultDescriptor,
    doc = "A **generalistic** (with wildcard xpubs) Unvault miniscript descriptor. \
            See the [unvault_descriptor] function for more information.",
    doc = "A **concrete** (with raw public keys) Unvault miniscript descriptor. \
            See the [unvault_descriptor] function for more information."
);

impl_descriptor_newtype!(
    CpfpDescriptor,
    DerivedCpfpDescriptor,
    doc = "A **generalistic** (with wildcard xpubs) CPFP miniscript descriptor. \
            See the [cpfp_descriptor] function for more information.",
    doc = "A **concrete** (with raw public keys) CPFP miniscript descriptor. \
            See the [cpfp_descriptor] function for more information."
);

impl DepositDescriptor {
    /// Get the xpub miniscript descriptor for the deposit outputs.
    ///
    /// The deposit policy is an N-of-N, so `thresh(len(all_pubkeys), all_pubkeys)`.
    ///
    /// # Examples
    /// ```rust
    /// use revault_tx::{scripts, miniscript::{bitcoin::{self, secp256k1, util::bip32}, DescriptorPublicKey, DescriptorTrait}};
    /// use std::str::FromStr;
    ///
    /// let first_stakeholder = DescriptorPublicKey::from_str("xpub6EHLFGpTTiZgHAHfBJ1LoepGFX5iyLeZ6CVtF9HhzeB1dkxLsEfkiJda78EKhSXuo2m8gQwAs4ZAbqaJixFYHMFWTL9DJX1KsAXS2VY5JJx/*").unwrap();
    /// let second_stakeholder = DescriptorPublicKey::from_str("xpub6F2U61Uh9FNX94mZE6EgdZ3p5Wg8af6MHzFhskEskkAZ9ns2uvsnHBskU47wYY63yiYv8WufvTuHCePwUjK9zhKT1Cce8JGLBptncpvALw6/*").unwrap();
    ///
    /// let deposit_descriptor =
    ///     scripts::DepositDescriptor::new(vec![first_stakeholder, second_stakeholder]).expect("Compiling descriptor");
    /// println!("Deposit descriptor: {}", deposit_descriptor.inner());
    ///
    /// let secp = secp256k1::Secp256k1::verification_only();
    /// println!("Tenth child witness script: {}", deposit_descriptor.derive(bip32::ChildNumber::from(10), &secp).inner().explicit_script());
    /// ```
    ///
    /// # Errors
    /// - If the passed slice contains less than 2 public keys.
    /// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
    /// bug.
    pub fn new(
        stakeholders: Vec<DescriptorPublicKey>,
    ) -> Result<DepositDescriptor, ScriptCreationError> {
        if stakeholders.len() < 2 {
            return Err(ScriptCreationError::BadParameters);
        }

        let pubkeys = stakeholders
            .into_iter()
            .map(Policy::Key)
            .collect::<Vec<Policy<DescriptorPublicKey>>>();

        let policy = Policy::Threshold(pubkeys.len(), pubkeys);

        // This handles the non-safe or malleable cases.
        let ms = policy.compile::<Segwitv0>()?;
        let desc = Descriptor::new_wsh(ms)?;
        if !desc.for_each_key(|k| k.as_key().is_deriveable()) {
            return Err(ScriptCreationError::NonWildcardKeys);
        }

        Ok(DepositDescriptor(desc))
    }
}

/// Get the miniscript descriptors for the unvault outputs.
///
/// The unvault policy allows either all the stakeholders to spend, or (the fund managers + the cosigners)
/// after a timelock.
///
/// # Examples
/// ```rust
/// use revault_tx::{scripts, miniscript::{bitcoin::{self, secp256k1, util::bip32}, DescriptorPublicKey, DescriptorTrait}};
/// use std::str::FromStr;
///
/// let first_stakeholder = DescriptorPublicKey::from_str("xpub6EHLFGpTTiZgHAHfBJ1LoepGFX5iyLeZ6CVtF9HhzeB1dkxLsEfkiJda78EKhSXuo2m8gQwAs4ZAbqaJixFYHMFWTL9DJX1KsAXS2VY5JJx/*").unwrap();
/// let second_stakeholder = DescriptorPublicKey::from_str("xpub6F2U61Uh9FNX94mZE6EgdZ3p5Wg8af6MHzFhskEskkAZ9ns2uvsnHBskU47wYY63yiYv8WufvTuHCePwUjK9zhKT1Cce8JGLBptncpvALw6/*").unwrap();
/// let third_stakeholder = DescriptorPublicKey::from_str("xpub6Br1DUfrzxTVGo1sanuKDCUmSxDfLRrxLQBqpMqygkQLkQWodoyvvGtUV8Rp3r6d6BNYvedBSU8c7whhn2U8haRVxsWwuQiZ9LoFp7jXPQA/*").unwrap();
///
/// let first_cosig = DescriptorPublicKey::from_str("02a489e0ea42b56148d212d325b7c67c6460483ff931c303ea311edfef667c8f35").unwrap();
/// let second_cosig = DescriptorPublicKey::from_str("02767e6dde4877dcbf64de8a45fe1a0575dfc6b0ed06648f1022412c172ebd875c").unwrap();
/// let third_cosig = DescriptorPublicKey::from_str("0371cdea381b365ea159a3cf4f14029d1bff5b36b4cf12ac9e42be6955d2ed4ecf").unwrap();
///
/// let first_manager = DescriptorPublicKey::from_str("xpub6Duq1ob3cQ8Wxees2fTGNK2wTsVjgTPQcKJiPquXY2rQJTDjeCxkXFxTCGhcunFDt26Ddz45KQu7pbLmmUGG2PXTRVx3iDpBPEhdrijJf4U/*").unwrap();
/// let second_manager = DescriptorPublicKey::from_str("xpub6EWL35hY9uZZs5Ljt6J3G2ZK1Tu4GPVkFdeGvMknG3VmwVRHhtadCaw5hdRDBgrmx1nPVHWjGBb5xeuC1BfbJzjjcic2gNm1aA7ywWjj7G8/*").unwrap();
///
///
/// let unvault_descriptor = scripts::UnvaultDescriptor::new(
///     vec![first_stakeholder, second_stakeholder, third_stakeholder],
///     vec![first_manager, second_manager],
///     1,
///     // Cosigners
///     vec![first_cosig, second_cosig, third_cosig],
///     // CSV
///     42
/// ).expect("Compiling descriptor");
/// println!("Unvault descriptor: {}", unvault_descriptor.inner());
///
/// let secp = secp256k1::Secp256k1::verification_only();
/// println!("Tenth child witness script: {}", unvault_descriptor.derive(bip32::ChildNumber::from(10), &secp).inner().explicit_script());
/// ```
///
/// # Errors
/// - If any of the slice contains no public key, or if the number of non_managers public keys is
/// not the same as the number of cosigners public key.
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
impl UnvaultDescriptor {
    pub fn new(
        stakeholders: Vec<DescriptorPublicKey>,
        managers: Vec<DescriptorPublicKey>,
        managers_threshold: usize,
        cosigners: Vec<DescriptorPublicKey>,
        csv_value: u32,
    ) -> Result<UnvaultDescriptor, ScriptCreationError> {
        if stakeholders.is_empty() || managers.is_empty() || cosigners.len() != stakeholders.len() {
            return Err(ScriptCreationError::BadParameters);
        }

        if managers_threshold > managers.len() {
            return Err(ScriptCreationError::BadParameters);
        }

        // Stakeholders' and managers' must be deriveable xpubs.
        for key in stakeholders.iter().chain(managers.iter()) {
            match key {
                DescriptorPublicKey::XPub(xpub) => {
                    if matches!(xpub.wildcard, Wildcard::None) {
                        return Err(ScriptCreationError::NonWildcardKeys);
                    }
                }
                DescriptorPublicKey::SinglePub(_) => {
                    return Err(ScriptCreationError::NonWildcardKeys);
                }
            }
        }
        // Cosigners' key may not be. We use DescriptorSinglePub for them downstream with static raw
        // keys, but it's not hardcoded into the type system there to allow a more generic usage.

        // We require the locktime to be in number of blocks, and of course to not be disabled.
        // TODO: use rust-miniscript's constants after upgrading!
        if (csv_value & (1 << 31)) != 0 || (csv_value & (1 << 22)) != 0 {
            return Err(ScriptCreationError::BadParameters);
        }

        let mut pubkeys = managers
            .into_iter()
            .map(Policy::Key)
            .collect::<Vec<Policy<DescriptorPublicKey>>>();
        let spenders_thres = Policy::Threshold(managers_threshold, pubkeys);

        pubkeys = stakeholders
            .into_iter()
            .map(Policy::Key)
            .collect::<Vec<Policy<DescriptorPublicKey>>>();
        let stakeholders_thres = Policy::Threshold(pubkeys.len(), pubkeys);

        pubkeys = cosigners
            .into_iter()
            .map(Policy::Key)
            .collect::<Vec<Policy<DescriptorPublicKey>>>();
        let cosigners_thres = Policy::Threshold(pubkeys.len(), pubkeys);

        let cosigners_and_csv = Policy::And(vec![cosigners_thres, Policy::Older(csv_value)]);

        let managers_and_cosigners_and_csv = Policy::And(vec![spenders_thres, cosigners_and_csv]);

        let policy = Policy::Or(vec![
            (1, stakeholders_thres),
            (9, managers_and_cosigners_and_csv),
        ]);

        // This handles the non-safe or malleable cases.
        let ms = policy.compile::<Segwitv0>()?;

        Ok(UnvaultDescriptor(Descriptor::new_wsh(ms)?))
    }
}

/// Get the miniscript descriptor for the unvault transaction CPFP output.
///
/// It's a basic 1-of-N between the fund managers.
///
/// # Errors
/// - If the policy compilation to miniscript failed, which should not happen (tm) and would be a
/// bug.
impl CpfpDescriptor {
    pub fn new(managers: Vec<DescriptorPublicKey>) -> Result<CpfpDescriptor, ScriptCreationError> {
        let pubkeys = managers
            .into_iter()
            .map(Policy::Key)
            .collect::<Vec<Policy<DescriptorPublicKey>>>();

        let policy = Policy::Threshold(1, pubkeys);

        // This handles the non-safe or malleable cases.
        let ms = policy.compile::<Segwitv0>()?;
        let desc = Descriptor::new_wsh(ms)?;
        if !desc.for_each_key(|k| k.as_key().is_deriveable()) {
            return Err(ScriptCreationError::NonWildcardKeys);
        }

        Ok(CpfpDescriptor(desc))
    }
}

/// The "emergency address", it's kept obfuscated for the entire duration of the vault and is
/// necessarily a v0 P2WSH
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmergencyAddress(Address);
impl EmergencyAddress {
    /// Create a new Emergency Address. Will error if the address isn't a v0 P2WSH
    pub fn from(address: Address) -> Result<EmergencyAddress, ScriptCreationError> {
        if address.script_pubkey().is_v0_p2wsh() {
            Ok(EmergencyAddress(address))
        } else {
            Err(ScriptCreationError::BadParameters)
        }
    }

    /// Get the address
    pub fn address(&self) -> &Address {
        &self.0
    }

    /// Get the address
    pub fn into_address(self) -> Address {
        self.0
    }
}

impl fmt::Display for EmergencyAddress {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", &self.0)
    }
}

#[cfg(feature = "use-serde")]
impl<'de> de::Deserialize<'de> for EmergencyAddress {
    fn deserialize<D>(deserializer: D) -> Result<EmergencyAddress, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let addr = Address::deserialize(deserializer)?;
        EmergencyAddress::from(addr).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {

    use super::{CpfpDescriptor, DepositDescriptor, ScriptCreationError, UnvaultDescriptor};

    use miniscript::{
        bitcoin::{
            secp256k1::{self},
            util::bip32,
            Network,
        },
        descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
        policy::compiler::CompilerError,
    };
    use rand::{rngs::SmallRng, RngCore, SeedableRng};

    fn rand_xpub<C: secp256k1::Signing>(
        rng: &mut SmallRng,
        secp: &secp256k1::Secp256k1<C>,
    ) -> bip32::ExtendedPrivKey {
        let mut rand_bytes = [0u8; 64];

        rng.fill_bytes(&mut rand_bytes);

        bip32::ExtendedPrivKey::new_master(Network::Bitcoin, &rand_bytes)
            .unwrap_or_else(|_| rand_xpub(rng, secp))
    }

    fn get_random_pubkey<C: secp256k1::Signing>(
        rng: &mut SmallRng,
        secp: &secp256k1::Secp256k1<C>,
    ) -> DescriptorPublicKey {
        let mut rand_bytes = [0u8; 64];

        rng.fill_bytes(&mut rand_bytes);

        DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, &rand_xpub(rng, secp)),
            derivation_path: bip32::DerivationPath::from(vec![]),
            wildcard: Wildcard::Unhardened,
        })
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
        let secp = secp256k1::Secp256k1::signing_only();

        let mut rng = SmallRng::from_entropy();
        for ((thresh, n_managers), n_stakeholders) in configurations.iter() {
            let managers = (0..*n_managers)
                .map(|_| get_random_pubkey(&mut rng, &secp))
                .collect::<Vec<DescriptorPublicKey>>();
            let stakeholders = (0..*n_stakeholders)
                .map(|_| get_random_pubkey(&mut rng, &secp))
                .collect::<Vec<DescriptorPublicKey>>();
            let cosigners = (0..*n_stakeholders)
                .map(|_| get_random_pubkey(&mut rng, &secp))
                .collect::<Vec<DescriptorPublicKey>>();

            UnvaultDescriptor::new(
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
            DepositDescriptor::new(
                managers
                    .clone()
                    .iter()
                    .chain(stakeholders.iter())
                    .cloned()
                    .collect::<Vec<DescriptorPublicKey>>(),
            )
            .expect(&format!(
                "Deposit descriptors creation error with ({}, {})",
                n_managers, n_stakeholders
            ));
            CpfpDescriptor::new(managers).expect(&format!(
                "CPFP descriptors creation error with ({}, {})",
                n_managers, n_stakeholders
            ));
        }
    }

    #[test]
    fn test_default_configuration_limits() {
        let mut rng = SmallRng::from_entropy();
        let secp = secp256k1::Secp256k1::signing_only();

        assert_eq!(
            DepositDescriptor::new(vec![get_random_pubkey(&mut rng, &secp)])
                .unwrap_err()
                .to_string(),
            ScriptCreationError::BadParameters.to_string()
        );

        assert_eq!(
            UnvaultDescriptor::new(
                vec![get_random_pubkey(&mut rng, &secp)],
                vec![get_random_pubkey(&mut rng, &secp)],
                1,
                vec![
                    get_random_pubkey(&mut rng, &secp),
                    get_random_pubkey(&mut rng, &secp)
                ],
                6
            )
            .unwrap_err()
            .to_string(),
            ScriptCreationError::BadParameters.to_string()
        );

        assert_eq!(
            UnvaultDescriptor::new(
                vec![get_random_pubkey(&mut rng, &secp)],
                vec![get_random_pubkey(&mut rng, &secp)],
                1,
                vec![get_random_pubkey(&mut rng, &secp)],
                4194305
            )
            .unwrap_err()
            .to_string(),
            ScriptCreationError::BadParameters.to_string()
        );

        assert_eq!(
            UnvaultDescriptor::new(
                vec![get_random_pubkey(&mut rng, &secp)],
                vec![get_random_pubkey(&mut rng, &secp)],
                2,
                vec![get_random_pubkey(&mut rng, &secp)],
                4194305
            )
            .unwrap_err()
            .to_string(),
            ScriptCreationError::BadParameters.to_string()
        );

        // Maximum N-of-N
        let participants = (0..99)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        DepositDescriptor::new(participants).expect("Should be OK: max allowed value");
        // Now hit the limit
        let participants = (0..100)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        assert_eq!(
            DepositDescriptor::new(participants)
                .unwrap_err()
                .to_string(),
            ScriptCreationError::PolicyCompilation(CompilerError::LimitsExceeded).to_string()
        );

        // Maximum 1-of-N
        let managers = (0..20)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        CpfpDescriptor::new(managers).expect("Should be OK, that's the maximum allowed value");
        // Hit the limit
        let managers = (0..21)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        assert_eq!(
            CpfpDescriptor::new(managers).unwrap_err().to_string(),
            ScriptCreationError::PolicyCompilation(CompilerError::LimitsExceeded).to_string()
        );

        // Maximum non-managers for 2 managers
        let stakeholders = (0..38)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        let managers = (0..2)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        let cosigners = (0..38)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        UnvaultDescriptor::new(stakeholders, managers, 2, cosigners, 145).unwrap();

        // Now hit the limit
        let stakeholders = (0..39)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        let managers = (0..2)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        let cosigners = (0..39)
            .map(|_| get_random_pubkey(&mut rng, &secp))
            .collect::<Vec<DescriptorPublicKey>>();
        assert_eq!(
            UnvaultDescriptor::new(stakeholders, managers, 2, cosigners, 32)
                .unwrap_err()
                .to_string(),
            ScriptCreationError::PolicyCompilation(CompilerError::LimitsExceeded).to_string()
        );
    }

    #[cfg(feature = "use-serde")]
    #[test]
    fn serde_parse_emer_address() {
        use super::EmergencyAddress;

        serde_json::from_str::<EmergencyAddress>(
            "\"bcrt1qrht43q4xt59vr9jytlmckgde6rcvhxcp392kx9\"",
        )
        .expect_err("P2WPKH");
        serde_json::from_str::<EmergencyAddress>(
            "\"bcrt1q5k05km5zn2g7kp0c230r0g8znuhlk4yynne3pwklh6xl82ed087sgr902c\"",
        )
        .expect("P2WSH");

        serde_json::from_str::<EmergencyAddress>("\"1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY\"")
            .expect_err("P2PKH");
        serde_json::from_str::<EmergencyAddress>("\"3DoB8fDRHcNxLCBcgLTvrpfQD5amk6sUce\"")
            .expect_err("P2SH");
        serde_json::from_str::<EmergencyAddress>("\"bc1qw3w0nt60tzh4xqdhx7hmf5uh0nczxhcr8lt7ec\"")
            .expect_err("P2WPKH (mainnet)");
        serde_json::from_str::<EmergencyAddress>(
            "\"bc1qnz0msqjqaw59zex2aw00rm565yg0rlpc5h3dvtps38w60ggw0seqwgjaa6\"",
        )
        .expect("P2WSH (mainnet)");
    }
}
