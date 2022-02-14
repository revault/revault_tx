//! # Revault PSBT outputs
//!
//! Wrappers around bitcoin's TxOut to statically check Revault transactions creation and ease
//! their PSBT management.

use crate::scripts::{
    DerivedCpfpDescriptor, DerivedDepositDescriptor, DerivedUnvaultDescriptor, EmergencyAddress,
};

use miniscript::{
    bitcoin::{util::bip32, Amount, PublicKey, Script, TxOut},
    DescriptorTrait,
};

use std::{collections::BTreeMap, fmt};

/// Map of a raw public key to the xpub used to derive it and its derivation path
pub type Bip32Deriv = BTreeMap<PublicKey, (bip32::Fingerprint, bip32::DerivationPath)>;

/// Any output of a Revault transaction.
pub trait RevaultTxOut: fmt::Debug + Clone + PartialEq {
    /// Get a reference to the inner txout
    fn txout(&self) -> &TxOut;

    /// Get the actual inner txout
    fn into_txout(self) -> TxOut;
}

/// An output of a Revault transaction that we manage "internally", ie for which we have the
/// descriptor.
pub trait RevaultInternalTxOut: fmt::Debug + Clone + PartialEq + RevaultTxOut {
    /// Get a reference to the inner witness script ("redeem Script of the witness program")
    fn witness_script(&self) -> &Script;

    /// Get the actual inner witness script ("redeem Script of the witness program")
    fn into_witness_script(self) -> Script;

    /// Get a reference to the map of public key to xpub source and derivation index
    fn bip32_derivation(&self) -> &Bip32Deriv;

    /// Get the actual map of public key to xpub source and derivation index
    fn into_bip32_derivation(self) -> Bip32Deriv;

    /// Get the maximum size, in weight units, a satisfaction for this scriptPubKey would cost.
    fn max_sat_weight(&self) -> usize {
        miniscript::descriptor::Wsh::new(
            miniscript::Miniscript::parse(self.witness_script())
                .expect("The witness_script is always created from a Miniscript"),
        )
        .expect("The witness_script is always a P2WSH")
        .max_satisfaction_weight()
        .expect("It's a sane Script, derived from a Miniscript")
    }
}

macro_rules! implem_revault_txout {
    ( $struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq, Default)]
        pub struct $struct_name {
            txout: TxOut,
            witness_script: Script,
            bip32_derivation: Bip32Deriv,
        }

        impl RevaultTxOut for $struct_name {
            fn txout(&self) -> &TxOut {
                &self.txout
            }

            fn into_txout(self) -> TxOut {
                self.txout
            }
        }

        impl RevaultInternalTxOut for $struct_name {
            fn witness_script(&self) -> &Script {
                &self.witness_script
            }

            fn into_witness_script(self) -> Script {
                self.witness_script
            }

            fn bip32_derivation(&self) -> &Bip32Deriv {
                &self.bip32_derivation
            }

            fn into_bip32_derivation(self) -> Bip32Deriv {
                self.bip32_derivation
            }
        }
    };
}

implem_revault_txout!(
    DepositTxOut,
    doc = "A deposit transaction output. Used by the [Deposit](crate::transactions::DepositTransaction), \
            the [Cancel](crate::transactions::CancelTransaction), and the \
            [Spend](crate::transactions::SpendTransaction)."
);
impl DepositTxOut {
    /// Create a new DepositTxOut out of the given Deposit script descriptor
    pub fn new(value: Amount, script_descriptor: &DerivedDepositDescriptor) -> DepositTxOut {
        DepositTxOut {
            txout: TxOut {
                value: value.as_sat(),
                script_pubkey: script_descriptor.inner().script_pubkey(),
            },
            witness_script: script_descriptor.inner().explicit_script(),
            bip32_derivation: script_descriptor
                .keys()
                .into_iter()
                .map(|k| {
                    (
                        k.key,
                        (k.origin.0, bip32::DerivationPath::from(&[k.origin.1][..])),
                    )
                })
                .collect(),
        }
    }
}

implem_revault_txout!(UnvaultTxOut, doc = "*The* Unvault transaction output.");
impl UnvaultTxOut {
    /// Create a new UnvaultTxOut out of the given Unvault script descriptor
    pub fn new(value: Amount, script_descriptor: &DerivedUnvaultDescriptor) -> UnvaultTxOut {
        UnvaultTxOut {
            txout: TxOut {
                value: value.as_sat(),
                script_pubkey: script_descriptor.inner().script_pubkey(),
            },
            witness_script: script_descriptor.inner().explicit_script(),
            bip32_derivation: script_descriptor
                .keys()
                .into_iter()
                .map(|k| {
                    (
                        k.key,
                        (k.origin.0, bip32::DerivationPath::from(&[k.origin.1][..])),
                    )
                })
                .collect(),
        }
    }
}

/// The Emergency Deep Vault, the destination of the Emergency transactions fund.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmergencyTxOut(TxOut);
impl EmergencyTxOut {
    /// Create a new EmergencyTxOut, note that we don't know the witness_script!
    pub fn new(address: EmergencyAddress, value: Amount) -> EmergencyTxOut {
        EmergencyTxOut(TxOut {
            script_pubkey: address.address().script_pubkey(),
            value: value.as_sat(),
        })
    }
}

impl RevaultTxOut for EmergencyTxOut {
    fn txout(&self) -> &TxOut {
        &self.0
    }

    fn into_txout(self) -> TxOut {
        self.0
    }
}

implem_revault_txout!(
    CpfpTxOut,
    doc = "The output attached to the [Unvault](crate::transactions::UnvaultTransaction) \
            so that the fund managers can fee-bump it."
);
impl CpfpTxOut {
    /// Create a new CpfpTxOut out of the given Cpfp descriptor
    pub fn new(value: Amount, script_descriptor: &DerivedCpfpDescriptor) -> CpfpTxOut {
        CpfpTxOut {
            txout: TxOut {
                value: value.as_sat(),
                script_pubkey: script_descriptor.inner().script_pubkey(),
            },
            witness_script: script_descriptor.inner().explicit_script(),
            bip32_derivation: script_descriptor
                .keys()
                .into_iter()
                .map(|k| {
                    (
                        k.key,
                        (k.origin.0, bip32::DerivationPath::from(&[k.origin.1][..])),
                    )
                })
                .collect(),
        }
    }
}

/// A [Spend](crate::transactions::SpendTransaction) output can be either a change one (DepositTxOut)
/// or a payee-controlled one (ExternalTxOut).
#[derive(Debug, Clone, PartialEq)]
pub struct SpendTxOut(TxOut);

impl SpendTxOut {
    pub fn new(txo: TxOut) -> Self {
        SpendTxOut(txo)
    }
}

impl RevaultTxOut for SpendTxOut {
    fn txout(&self) -> &TxOut {
        &self.0
    }

    fn into_txout(self) -> TxOut {
        self.0
    }
}
