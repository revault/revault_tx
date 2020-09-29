//! Revault txins
//! Wrappers around bitcoin's OutPoint and previous TxOut to statically check Revault transaction
//! creation and ease PSBT management.

use crate::txouts::{CpfpTxOut, FeeBumpTxOut, UnvaultTxOut, VaultTxOut};

use bitcoin::{OutPoint, TxIn};

use std::fmt;

/// A transaction input used by a Revault transaction.
pub trait RevaultTxIn<T>: fmt::Debug + Clone + PartialEq {
    /// Get the actual outpoint
    fn outpoint(&self) -> OutPoint;
    /// Get a reference to the txout this txin refers
    fn as_txout(&self) -> &T;
    /// Get the actual txout this txin refers
    fn into_txout(self) -> T;
    /// Get an actual Bitcoin TxIn out of the OutPoint and the nSequence
    fn as_unsigned_txin(&self) -> TxIn;
}

macro_rules! implem_revault_txin {
    ( $struct_name:ident, $txout_struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq)]
        pub struct $struct_name {
            outpoint: OutPoint,
            prev_txout: $txout_struct_name,
            sequence: u32,
        }

        impl RevaultTxIn<$txout_struct_name> for $struct_name {
            fn outpoint(&self) -> OutPoint {
                self.outpoint
            }

            fn as_txout(&self) -> &$txout_struct_name {
                &self.prev_txout
            }

            fn into_txout(self) -> $txout_struct_name {
                self.prev_txout
            }

            fn as_unsigned_txin(&self) -> TxIn {
                TxIn {
                    previous_output: self.outpoint,
                    sequence: self.sequence,
                    ..TxIn::default()
                }
            }
        }
    };
}

implem_revault_txin!(
    VaultTxIn,
    VaultTxOut,
    doc = "A vault txo spent by the unvault transaction and the emergency transaction"
);
impl VaultTxIn {
    /// Instanciate a TxIn referencing a vault txout
    pub fn new(outpoint: OutPoint, prev_txout: VaultTxOut, sequence: u32) -> VaultTxIn {
        VaultTxIn {
            outpoint,
            prev_txout,
            sequence,
        }
    }
}

implem_revault_txin!(
    UnvaultTxIn,
    UnvaultTxOut,
    doc="An unvault txo spent by the cancel transaction, an emergency transaction, and the spend transaction."
);
impl UnvaultTxIn {
    /// Instanciate a TxIn referencing an unvault txout
    pub fn new(outpoint: OutPoint, prev_txout: UnvaultTxOut, sequence: u32) -> UnvaultTxIn {
        UnvaultTxIn {
            outpoint,
            prev_txout,
            sequence,
        }
    }
}

implem_revault_txin!(
    FeeBumpTxIn,
    FeeBumpTxOut,
    doc = "A wallet txo spent by a revaulting (cancel, emergency) transaction to bump the transaction feerate.\
           This output is often created by a first stage transaction, but may directly be a wallet\
           utxo."
);
impl FeeBumpTxIn {
    /// Instanciate a txin referencing a feebumpt txout
    pub fn new(outpoint: OutPoint, prev_txout: FeeBumpTxOut, sequence: u32) -> FeeBumpTxIn {
        FeeBumpTxIn {
            outpoint,
            prev_txout,
            sequence,
        }
    }
}

implem_revault_txin!(
    CpfpTxIn,
    CpfpTxOut,
    doc = "The unvault CPFP txo spent to accelerate the confirmation of the unvault transaction."
);
impl CpfpTxIn {
    /// Instanciate a TxIn referencing a CPFP txout
    pub fn new(outpoint: OutPoint, prev_txout: CpfpTxOut, sequence: u32) -> CpfpTxIn {
        CpfpTxIn {
            outpoint,
            prev_txout,
            sequence,
        }
    }
}
