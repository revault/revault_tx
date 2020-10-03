//! Revault txouts
//! Wrappers around bitcoin's TxOut to statically check Revault transaction creation and ease
//! their PSBT management.

use crate::scripts::{CpfpDescriptor, UnvaultDescriptor, VaultDescriptor};

use bitcoin::{Script, TxOut};
use miniscript::{MiniscriptKey, ToPublicKey};

use std::fmt;

/// A transaction output created by a Revault transaction.
pub trait RevaultTxOut: fmt::Debug + Clone + PartialEq {
    /// Get a reference to the inner txout
    fn inner_txout(&self) -> &TxOut;
    /// Get the actual inner txout
    fn get_txout(self) -> TxOut;
    /// Get a reference to the inner witness script ("redeem Script of the witness program")
    fn witness_script(&self) -> &Option<Script>;
    /// Get the actual inner witness script ("redeem Script of the witness program")
    fn into_witness_script(self) -> Option<Script>;
}

macro_rules! implem_revault_txout {
    ( $struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq)]
        pub struct $struct_name {
            txout: TxOut,
            witness_script: Option<Script>,
        }

        impl RevaultTxOut for $struct_name {
            fn inner_txout(&self) -> &TxOut {
                &self.txout
            }

            fn get_txout(self) -> TxOut {
                self.txout
            }

            fn witness_script(&self) -> &Option<Script> {
                &self.witness_script
            }

            fn into_witness_script(self) -> Option<Script> {
                self.witness_script
            }
        }
    };
}

implem_revault_txout!(
    VaultTxOut,
    doc = "A vault transaction output. Used by the funding / deposit transactions, the cancel transactions, and the spend transactions (for the change)."
);
impl VaultTxOut {
    /// Create a new VaultTxOut out of the given Vault script descriptor
    pub fn new<Pk: MiniscriptKey + ToPublicKey>(
        value: u64,
        script_descriptor: &VaultDescriptor<Pk>,
    ) -> VaultTxOut {
        VaultTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.0.script_pubkey(),
            },
            witness_script: Some(script_descriptor.0.witness_script()),
        }
    }
}

implem_revault_txout!(UnvaultTxOut, doc = "*The* unvault transaction output.");
impl UnvaultTxOut {
    /// Create a new UnvaultTxOut out of the given Unvault script descriptor
    pub fn new<Pk: MiniscriptKey + ToPublicKey>(
        value: u64,
        script_descriptor: &UnvaultDescriptor<Pk>,
    ) -> UnvaultTxOut {
        UnvaultTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.0.script_pubkey(),
            },
            witness_script: Some(script_descriptor.0.witness_script()),
        }
    }
}

implem_revault_txout!(
    EmergencyTxOut,
    doc = "The Emergency Deep Vault, the destination of the emergency transactions fund."
);
impl EmergencyTxOut {
    /// Create a new EmergencyTxOut, note that we don't know the witness_script!
    pub fn new(txout: TxOut) -> EmergencyTxOut {
        EmergencyTxOut {
            txout,
            witness_script: None,
        }
    }
}

implem_revault_txout!(
    CpfpTxOut,
    doc = "The output attached to the unvault transaction so that the fund managers can CPFP."
);
impl CpfpTxOut {
    /// Create a new CpfpTxOut out of the given Cpfp descriptor
    pub fn new<Pk: MiniscriptKey + ToPublicKey>(
        value: u64,
        script_descriptor: &CpfpDescriptor<Pk>,
    ) -> CpfpTxOut {
        CpfpTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.0.script_pubkey(),
            },
            witness_script: Some(script_descriptor.0.witness_script()),
        }
    }
}

implem_revault_txout!(
    FeeBumpTxOut,
    doc = "The output spent by the revaulting transactions to bump their feerate"
);
impl FeeBumpTxOut {
    /// Create a new FeeBumpTxOut, note that it's managed externally so we don't need a witness
    /// Script.
    pub fn new(txout: TxOut) -> FeeBumpTxOut {
        FeeBumpTxOut {
            txout,
            witness_script: None,
        }
    }
}

implem_revault_txout!(
    ExternalTxOut,
    doc = "An untagged external output, as spent by the vault transaction or created by the spend transaction."
);
impl ExternalTxOut {
    /// Create a new ExternalTxOut, note that it's managed externally so we don't need a witness
    /// Script.
    pub fn new(txout: TxOut) -> ExternalTxOut {
        ExternalTxOut {
            txout,
            witness_script: None,
        }
    }
}

/// A spend transaction output can be either a change one (VaultTxOut) or a payee-controlled
/// one (ExternalTxOut).
pub enum SpendTxOut {
    /// The actual destination of the funds, many such output can be present in a Spend
    /// transaction
    Destination(ExternalTxOut),
    /// The change output, usually only one such output is present in a Spend transaction
    Change(VaultTxOut),
}
