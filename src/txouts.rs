//! Revault txouts
//! Wrappers around bitcoin's TxOut to statically check Revault transactions creation and ease
//! their PSBT management.

use crate::{
    error::TxoutCreationError,
    scripts::{CpfpDescriptor, DepositDescriptor, EmergencyAddress, UnvaultDescriptor},
};

use miniscript::{
    bitcoin::{Script, TxOut},
    MiniscriptKey, ToPublicKey,
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
    doc = "A deposit transaction output. Used by the funding / deposit transactions, the cancel transactions, and the spend transactions (for the change)."
);
impl DepositTxOut {
    /// Create a new DepositTxOut out of the given Deposit script descriptor
    pub fn new<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        value: u64,
        script_descriptor: &DepositDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
    ) -> DepositTxOut {
        DepositTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.0.script_pubkey(to_pk_ctx),
            },
            witness_script: Some(script_descriptor.0.witness_script(to_pk_ctx)),
        }
    }
}

implem_revault_txout!(UnvaultTxOut, doc = "*The* unvault transaction output.");
impl UnvaultTxOut {
    /// Create a new UnvaultTxOut out of the given Unvault script descriptor
    pub fn new<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        value: u64,
        script_descriptor: &UnvaultDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
    ) -> UnvaultTxOut {
        UnvaultTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.0.script_pubkey(to_pk_ctx),
            },
            witness_script: Some(script_descriptor.0.witness_script(to_pk_ctx)),
        }
    }
}

implem_revault_txout!(
    EmergencyTxOut,
    doc = "The Emergency Deep Vault, the destination of the emergency transactions fund."
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
    doc = "The output attached to the unvault transaction so that the fund managers can CPFP."
);
impl CpfpTxOut {
    /// Create a new CpfpTxOut out of the given Cpfp descriptor
    pub fn new<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        value: u64,
        script_descriptor: &CpfpDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
    ) -> CpfpTxOut {
        CpfpTxOut {
            txout: TxOut {
                value,
                script_pubkey: script_descriptor.0.script_pubkey(to_pk_ctx),
            },
            witness_script: Some(script_descriptor.0.witness_script(to_pk_ctx)),
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
    doc = "An untagged external output, as spent by the deposit transaction or created by the spend transaction."
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

/// A spend transaction output can be either a change one (DepositTxOut) or a payee-controlled
/// one (ExternalTxOut).
#[derive(Debug, Clone)]
pub enum SpendTxOut {
    /// The actual destination of the funds, many such output can be present in a Spend
    /// transaction
    Destination(ExternalTxOut),
    /// The change output, usually only one such output is present in a Spend transaction
    Change(DepositTxOut),
}
