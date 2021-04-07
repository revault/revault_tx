//! # Revault PSBT outputs
//!
//! Wrappers around bitcoin's TxOut to statically check Revault transactions creation and ease
//! their PSBT management.

use crate::{
    error::TxoutCreationError,
    scripts::{
        DerivedCpfpDescriptor, DerivedDepositDescriptor, DerivedUnvaultDescriptor, EmergencyAddress,
    },
};

use miniscript::{
    bitcoin::{Script, TxOut},
    DescriptorTrait,
};

use std::fmt;

/// A transaction output created by a Revault transaction.
pub trait RevaultTxOut: fmt::Debug + Clone + PartialEq {
    /// Get a reference to the inner txout
    fn txout(&self) -> &TxOut;
    /// Get the actual inner txout
    fn into_txout(self) -> TxOut;
    /// Get a reference to the inner witness script ("redeem Script of the witness program")
    fn witness_script(&self) -> &Option<Script>;
    /// Get the actual inner witness script ("redeem Script of the witness program")
    fn into_witness_script(self) -> Option<Script>;
}

macro_rules! implem_revault_txout {
    ( $struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq, Default)]
        pub struct $struct_name {
            txout: TxOut,
            witness_script: Option<Script>,
        }

        impl RevaultTxOut for $struct_name {
            fn txout(&self) -> &TxOut {
                &self.txout
            }

            fn into_txout(self) -> TxOut {
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
    DepositTxOut,
    doc = "A deposit transaction output. Used by the [Deposit](crate::transactions::DepositTransaction), \
            the [Cancel](crate::transactions::CancelTransaction), and the \
            [Spend](crate::transactions::SpendTransaction)."
);
impl DepositTxOut {
    /// Create a new DepositTxOut out of the given Deposit script descriptor
    pub fn new(value: u64, script_descriptor: &DerivedDepositDescriptor) -> DepositTxOut {
        DepositTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.inner().script_pubkey(),
            },
            witness_script: Some(script_descriptor.inner().explicit_script()),
        }
    }
}

implem_revault_txout!(UnvaultTxOut, doc = "*The* Unvault transaction output.");
impl UnvaultTxOut {
    /// Create a new UnvaultTxOut out of the given Unvault script descriptor
    pub fn new(value: u64, script_descriptor: &DerivedUnvaultDescriptor) -> UnvaultTxOut {
        UnvaultTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.inner().script_pubkey(),
            },
            witness_script: Some(script_descriptor.inner().explicit_script()),
        }
    }
}

implem_revault_txout!(
    EmergencyTxOut,
    doc = "The Emergency Deep Vault, the destination of the Emergency transactions fund."
);
impl EmergencyTxOut {
    /// Create a new EmergencyTxOut, note that we don't know the witness_script!
    pub fn new(address: EmergencyAddress, value: u64) -> EmergencyTxOut {
        EmergencyTxOut {
            txout: TxOut {
                script_pubkey: address.address().script_pubkey(),
                value,
            },
            witness_script: None,
        }
    }
}

implem_revault_txout!(
    CpfpTxOut,
    doc = "The output attached to the [Unvault](crate::transactions::UnvaultTransaction) \
            so that the fund managers can fee-bump it."
);
impl CpfpTxOut {
    /// Create a new CpfpTxOut out of the given Cpfp descriptor
    pub fn new(value: u64, script_descriptor: &DerivedCpfpDescriptor) -> CpfpTxOut {
        CpfpTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.inner().script_pubkey(),
            },
            witness_script: Some(script_descriptor.inner().explicit_script()),
        }
    }
}

implem_revault_txout!(
    FeeBumpTxOut,
    doc = "The output spent by the revocation transactions to bump their feerate"
);
impl FeeBumpTxOut {
    /// Create a new FeeBumpTxOut, note that it's managed externally so we don't need a witness
    /// Script.
    pub fn new(txout: TxOut) -> Result<FeeBumpTxOut, TxoutCreationError> {
        if !txout.script_pubkey.is_v0_p2wpkh() {
            return Err(TxoutCreationError::InvalidScriptPubkeyType);
        }

        Ok(FeeBumpTxOut {
            txout,
            witness_script: None,
        })
    }
}

implem_revault_txout!(
    ExternalTxOut,
    doc = "An untagged external output, as spent / created by the \
            [Deposit](crate::transactions::DepositTransaction) or created by the \
            [Spend](crate::transactions::SpendTransaction)."
);
impl ExternalTxOut {
    /// Create an external txout, hence without a witness script.
    pub fn new(txout: TxOut) -> ExternalTxOut {
        ExternalTxOut {
            txout,
            witness_script: None,
        }
    }
}

/// A [Spend](crate::transactions::SpendTransaction) output can be either a change one (DepositTxOut)
/// or a payee-controlled one (ExternalTxOut).
#[derive(Debug, Clone)]
pub enum SpendTxOut {
    /// The actual destination of the funds, many such output can be present in a Spend
    /// transaction
    Destination(ExternalTxOut),
    /// The change output, usually only one such output is present in a Spend transaction
    Change(DepositTxOut),
}
