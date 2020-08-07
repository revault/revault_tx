use super::revault_error::RevaultError;

use bitcoin::{OutPoint, Transaction, TxIn, TxOut};

const RBF_SEQUENCE: u32 = u32::MAX - 2;

#[derive(Debug)]
pub enum RevaultTxOut {
    VaultTxOut(TxOut),
    UnvaultTxOut(TxOut),
    SpendTxOut(TxOut),
    EmergencyTxOut(TxOut),
    FeeBumpTxOut(TxOut),
}

#[derive(Debug)]
pub enum RevaultPrevout {
    VaultPrevout(OutPoint),
    UnvaultPrevout(OutPoint),
    SpendPrevout(OutPoint),
    CancelPrevout(OutPoint),
    EmergencyPrevout(OutPoint),
    FeeBumpPrevout(OutPoint),
}

#[derive(Debug)]
pub enum RevaultTransaction {
    UnvaultTransaction(Transaction),
    SpendTransaction(Transaction),
    CancelTransaction(Transaction),
    EmergencyTransaction(Transaction),
}

// Using a struct wrapper around the enum wrapper to create an encapsulation behaviour would be
// quite verbose..
impl RevaultTransaction {
    pub fn new_unvault(
        prevouts: &[RevaultPrevout; 1],
        txouts: &[RevaultTxOut; 2],
    ) -> Result<Self, RevaultError> {
        // An unvault transaction always spends one vault txout and contains one CPFP txout
        // in addition to the unvault one.
        match (prevouts, txouts) {
            (
                [RevaultPrevout::VaultPrevout(ref vault_prevout)],
                [RevaultTxOut::UnvaultTxOut(ref unvault_txout), RevaultTxOut::FeeBumpTxOut(ref cpfp_txout)],
            ) => {
                let vault_input = TxIn {
                    previous_output: vault_prevout.clone(),
                    ..Default::default()
                };
                Ok(RevaultTransaction::UnvaultTransaction(Transaction {
                    version: 2,
                    lock_time: 0, // FIXME: anti fee snipping
                    input: vec![vault_input],
                    output: vec![unvault_txout.clone(), cpfp_txout.clone()],
                }))
            }
            _ => Err(RevaultError::TransactionCreation(format!(
                "Unvault: type mismatch on prevout ({:?}) or output(s) ({:?})",
                prevouts, txouts
            ))),
        }
    }

    pub fn new_spend(
        prevouts: &[RevaultPrevout],
        txouts: &[RevaultTxOut],
        csv_value: u32,
    ) -> Result<Self, RevaultError> {
        // A spend transaction can batch multiple unvault txouts, and may have any number of
        // txouts (including, but not restricted to, change).
        match (prevouts, txouts) {
            (&[RevaultPrevout::UnvaultPrevout(_)], &[RevaultTxOut::SpendTxOut(_)]) => {
                let inputs = prevouts
                    .iter()
                    .map(|prevout| TxIn {
                        previous_output: match prevout {
                            RevaultPrevout::UnvaultPrevout(ref prev) => prev.clone(),
                            _ => unreachable!(),
                        },
                        sequence: csv_value,
                        ..Default::default()
                    })
                    .collect();

                let txouts = txouts
                    .iter()
                    .map(|txout| match txout {
                        RevaultTxOut::SpendTxOut(ref out) => out.clone(),
                        _ => unreachable!(),
                    })
                    .collect();

                Ok(RevaultTransaction::SpendTransaction(Transaction {
                    version: 2,
                    lock_time: 0,
                    input: inputs,
                    output: txouts,
                }))
            }
            _ => Err(RevaultError::TransactionCreation(format!(
                "Spend transaction: prevouts ({:?}) or output(s) ({:?}) type mismatch",
                prevouts, txouts
            ))),
        }
    }

    pub fn new_cancel(
        prevouts: &[RevaultPrevout],
        txouts: &[RevaultTxOut],
    ) -> Result<RevaultTransaction, RevaultError> {
        // A cancel transaction always pays to a vault output and spend the unvault output
        // but may have a fee-bumping input.
        match (prevouts, txouts) {
            // FIXME: Use https://github.com/rust-lang/rust/issues/54883 once stabilized ..
            (
                &[RevaultPrevout::UnvaultPrevout(_)],
                &[RevaultTxOut::VaultTxOut(ref vault_txout)],
            )
            | (
                &[RevaultPrevout::UnvaultPrevout(_), RevaultPrevout::FeeBumpPrevout(_)],
                &[RevaultTxOut::VaultTxOut(ref vault_txout)],
            ) => {
                let inputs = prevouts
                    .iter()
                    .map(|prevout| TxIn {
                        previous_output: match prevout {
                            RevaultPrevout::UnvaultPrevout(ref prev)
                            | RevaultPrevout::FeeBumpPrevout(ref prev) => prev.clone(),
                            _ => unreachable!(),
                        },
                        sequence: RBF_SEQUENCE,
                        ..Default::default()
                    })
                    .collect();

                Ok(RevaultTransaction::CancelTransaction(Transaction {
                    version: 2,
                    lock_time: 0,
                    input: inputs,
                    output: vec![vault_txout.clone()],
                }))
            }
            _ => Err(RevaultError::TransactionCreation(format!(
                "Cancel transaction prevouts ({:?}) or outputs ({:?}) type mismatch",
                prevouts, txouts,
            ))),
        }
    }

    pub fn new_emergency(
        prevouts: &[RevaultPrevout],
        txouts: &[RevaultTxOut],
    ) -> Result<RevaultTransaction, RevaultError> {
        // There are two emergency transactions, one spending the vault output and one spending
        // the unvault output. Both may have a fee-bumping input.
        match (prevouts, txouts) {
            // When or patterns :'(
            (
                &[RevaultPrevout::VaultPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            )
            | (
                &[RevaultPrevout::VaultPrevout(_), RevaultPrevout::FeeBumpPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            )
            | (
                &[RevaultPrevout::UnvaultPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            )
            | (
                &[RevaultPrevout::UnvaultPrevout(_), RevaultPrevout::FeeBumpPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            ) => {
                let inputs = prevouts
                    .iter()
                    .map(|prevout| TxIn {
                        previous_output: match prevout {
                            RevaultPrevout::VaultPrevout(ref prev)
                            | RevaultPrevout::UnvaultPrevout(ref prev)
                            | RevaultPrevout::FeeBumpPrevout(ref prev) => prev.clone(),
                            _ => unreachable!(),
                        },
                        sequence: RBF_SEQUENCE,
                        ..Default::default()
                    })
                    .collect();

                Ok(RevaultTransaction::EmergencyTransaction(Transaction {
                    version: 2,
                    lock_time: 0,
                    input: inputs,
                    output: vec![emer_txout.clone()],
                }))
            }
            _ => Err(RevaultError::TransactionCreation(format!(
                "Emergency transaction prevouts ({:?}) or outputs ({:?}) type mismatch",
                prevouts, txouts,
            ))),
        }
    }
}
