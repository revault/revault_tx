//! Revault prevouts
//! Tiny newtype wrappers around bitcoin's OutPoint to statically check Revault transaction
//! creation.

use bitcoin::OutPoint;

use std::fmt;

/// A transaction output spent by a Revault transaction.
pub trait RevaultPrevout: fmt::Debug + Copy + PartialEq {
    /// Get the actual outpoint
    fn outpoint(&self) -> OutPoint;
}

macro_rules! implem_revault_prevout {
    ( $struct_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Copy, Clone, PartialEq)]
        pub struct $struct_name(OutPoint);

        impl $struct_name {
            /// Create a new prevout, the sequence will be set to 0xff_ff_ff_ff is None
            pub fn new(outpoint: OutPoint) -> $struct_name {
                $struct_name(outpoint)
            }
        }

        impl RevaultPrevout for $struct_name {
            fn outpoint(&self) -> OutPoint {
                self.0
            }
        }
    };
}

implem_revault_prevout!(
    VaultPrevout,
    doc = "A vault txo spent by the unvault transaction and the emergency transaction"
);

implem_revault_prevout!(
    UnvaultPrevout,
    doc="An unvault txo spent by the cancel transaction, an emergency transaction, and the spend transaction."
);

implem_revault_prevout!(
    FeeBumpPrevout,
    doc = "A wallet txo spent by a revaulting (cancel, emergency) transaction to bump the transaction feerate.\
           This output is often created by a first stage transaction, but may directly be a wallet\
           utxo."
);

implem_revault_prevout!(
    CpfpPrevout,
    doc = "The unvault CPFP txo spent to accelerate the confirmation of the unvault transaction."
);
