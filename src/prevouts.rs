//! Revault prevouts
//! Wrappers around bitcoin's OutPoint to statically check Revault transaction creation and ease
//! PSBT management.

use crate::txouts::{CpfpTxOut, FeeBumpTxOut, UnvaultTxOut, VaultTxOut};

use bitcoin::OutPoint;

use std::fmt;

/// A transaction output spent by a Revault transaction.
pub trait RevaultPrevout<T>: fmt::Debug + Clone + PartialEq {
    /// Get the actual outpoint
    fn outpoint(&self) -> OutPoint;
    /// Get a reference to the txout this prevout refers to
    fn as_txout(&self) -> &T;
    /// Get the actual txout this prevout refers to
    fn into_txout(self) -> T;
}

macro_rules! implem_revault_prevout {
    ( $struct_name:ident, $txout_struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq)]
        pub struct $struct_name {
            outpoint: OutPoint,
            prev_txout: $txout_struct_name,
        }

        impl RevaultPrevout<$txout_struct_name> for $struct_name {
            fn outpoint(&self) -> OutPoint {
                self.outpoint
            }

            fn as_txout(&self) -> &$txout_struct_name {
                &self.prev_txout
            }

            fn into_txout(self) -> $txout_struct_name {
                self.prev_txout
            }
        }
    };
}

implem_revault_prevout!(
    VaultPrevout,
    VaultTxOut,
    doc = "A vault txo spent by the unvault transaction and the emergency transaction"
);
impl VaultPrevout {
    /// Instanciate a prevout pointing to a vault txout
    pub fn new(outpoint: OutPoint, prev_txout: VaultTxOut) -> VaultPrevout {
        VaultPrevout {
            outpoint,
            prev_txout,
        }
    }
}

implem_revault_prevout!(
    UnvaultPrevout,
    UnvaultTxOut,
    doc="An unvault txo spent by the cancel transaction, an emergency transaction, and the spend transaction."
);
impl UnvaultPrevout {
    /// Instanciate a prevout pointing to an unvault txout
    pub fn new(outpoint: OutPoint, prev_txout: UnvaultTxOut) -> UnvaultPrevout {
        UnvaultPrevout {
            outpoint,
            prev_txout,
        }
    }
}

implem_revault_prevout!(
    FeeBumpPrevout,
    FeeBumpTxOut,
    doc = "A wallet txo spent by a revaulting (cancel, emergency) transaction to bump the transaction feerate.\
           This output is often created by a first stage transaction, but may directly be a wallet\
           utxo."
);
impl FeeBumpPrevout {
    /// Instanciate a prevout pointing to a feebumpt txout
    pub fn new(outpoint: OutPoint, prev_txout: FeeBumpTxOut) -> FeeBumpPrevout {
        FeeBumpPrevout {
            outpoint,
            prev_txout,
        }
    }
}

implem_revault_prevout!(
    CpfpPrevout,
    CpfpTxOut,
    doc = "The unvault CPFP txo spent to accelerate the confirmation of the unvault transaction."
);
impl CpfpPrevout {
    /// Instanciate a prevout pointing to a CPFP txout
    pub fn new(outpoint: OutPoint, prev_txout: CpfpTxOut) -> CpfpPrevout {
        CpfpPrevout {
            outpoint,
            prev_txout,
        }
    }
}
