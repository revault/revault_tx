//! Revault txouts
//! Tiny newtype wrappers around bitcoin's TxOut to statically check Revault transaction
//! creation.

use bitcoin::TxOut;

use std::fmt;

/// A transaction output created by a Revault transaction.
pub trait RevaultTxOut: fmt::Debug + Clone {
    /// Get a reference to the inner txout
    fn inner_txout(&self) -> &TxOut;
    /// Get the actual inner txout
    fn get_txout(self) -> TxOut;
}

macro_rules! implem_revault_txout {
    ( $struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone)]
        pub struct $struct_name(TxOut);

        impl RevaultTxOut for $struct_name {
            fn inner_txout(&self) -> &TxOut {
                &self.0
            }

            fn get_txout(self) -> TxOut {
                self.0
            }
        }

        impl $struct_name {
            /// Create a new RevaultTxOut
            pub fn new(txout: TxOut) -> $struct_name {
                $struct_name(txout)
            }
        }
    };
}

implem_revault_txout!(
    VaultTxOut,
    doc = "A vault transaction output. Used by the funding / deposit transactions, the cancel transactions, and the spend transactions (for the change)."
);

implem_revault_txout!(UnvaultTxOut, doc = "*The* unvault transaction output.");

implem_revault_txout!(
    EmergencyTxOut,
    doc = "The Emergency Deep Vault, the destination of the emergency transactions fund."
);

implem_revault_txout!(
    CpfpTxOut,
    doc = "The output attached to the unvault transaction so that the fund managers can CPFP."
);

implem_revault_txout!(
    FeeBumpTxOut,
    doc = "The output spent by the revaulting transactions to bump their feerate"
);

implem_revault_txout!(
    ExternalTxOut,
    doc = "An untagged external output, as spent by the vault transaction or created by the spend transaction."
);

/// A spend transaction output can be either a change one (VaultTxOut) or a payee-controlled
/// one (ExternalTxOut).
pub enum SpendTxOut {
    /// The actual destination of the funds, many such output can be present in a Spend
    /// transaction
    Destination(ExternalTxOut),
    /// The change output, usually only one such output is present in a Spend transaction
    Change(VaultTxOut),
}
