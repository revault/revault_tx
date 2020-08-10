///! Revault transactions
///!
///! Typesafe routines to create bare revault transactions.
///!
use super::revault_error::RevaultError;

#[allow(clippy::all)]
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};

const RBF_SEQUENCE: u32 = u32::MAX - 2;

/// A transaction output created by a Revault transaction.
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub enum RevaultTxOut {
    /// A vault transaction output. Used by the funding / deposit transactions, the cancel
    /// transactions, and the spend transactions (for the change).
    VaultTxOut(TxOut),
    /// *The* unvault transaction output.
    UnvaultTxOut(TxOut),
    /// A spend transaction output. As Revault is flexible by default with regard to the
    /// destination of the spend transaction funds, any number of these can be present in a spend
    /// transaction (use a VaultTxOut for the change output however).
    SpendTxOut(TxOut),
    /// The Emergency Deep Vault, the destination of the emergency transactions fund.
    EmergencyTxOut(TxOut),
    /// The "fee bumping" output, attached to the unvault transaction so that the fund managers can
    /// CPFP.
    CpfpTxOut(TxOut),
}

/// A transaction output spent by a Revault transaction.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash, PartialOrd, Ord)]
pub enum RevaultPrevout {
    /// A vault txo spent by the unvault transaction and the emergency transaction.
    VaultPrevout(OutPoint),
    /// An unvault txo spent by the cancel transaction, an emergency transaction, and
    /// the spend transaction.
    UnvaultPrevout(OutPoint),
    /// A wallet txo possibly spent by the cancel transaction and the emergency transactions to
    /// bump the transaction feerate.
    WalletPrevout(OutPoint),
    /// The unvault CPFP txo spent to accelerate the confirmation of the unvault transaction.
    CpfpPrevout(OutPoint),
}

// Using a struct wrapper around the enum wrapper to create an encapsulation behaviour would be
// quite verbose..

/// A Revault transaction. Must be instanciated using the new_*() methods.
#[derive(PartialEq, Eq, Debug)]
pub enum RevaultTransaction {
    /// The unvaulting transaction, spending a vault and being eventually spent by a spend
    /// transaction (if not revaulted).
    UnvaultTransaction(Transaction),
    /// The transaction spending the unvaulting transaction, paying to one or multiple
    /// externally-controlled addresses, and possibly to a new vault txo for the change.
    SpendTransaction(Transaction),
    /// The transaction "revaulting" a spend attempt, i.e. spending the unvaulting transaction back
    /// to a vault txo.
    CancelTransaction(Transaction),
    /// The transaction spending either a vault or unvault txo to The Emergency Deep Vault.
    EmergencyTransaction(Transaction),
}

impl RevaultTransaction {
    /// Create an unvault transaction.
    /// An unvault transaction always spends one vault txout and contains one CPFP txout in
    /// addition to the unvault one.
    pub fn new_unvault(
        prevouts: &[RevaultPrevout; 1],
        txouts: &[RevaultTxOut; 2],
    ) -> Result<RevaultTransaction, RevaultError> {
        match (prevouts, txouts) {
            (
                [RevaultPrevout::VaultPrevout(ref vault_prevout)],
                [RevaultTxOut::UnvaultTxOut(ref unvault_txout), RevaultTxOut::CpfpTxOut(ref cpfp_txout)],
            ) => {
                let vault_input = TxIn {
                    previous_output: *vault_prevout,
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

    /// Create a new spend transaction.
    /// A spend transaction can batch multiple unvault txouts, and may have any number of
    /// txouts (including, but not restricted to, change).
    pub fn new_spend(
        prevouts: &[RevaultPrevout],
        outputs: &[RevaultTxOut],
        csv_value: u32,
    ) -> Result<RevaultTransaction, RevaultError> {
        let mut txins = Vec::<TxIn>::with_capacity(prevouts.len());
        for prevout in prevouts {
            if let RevaultPrevout::UnvaultPrevout(ref prev) = prevout {
                txins.push(TxIn {
                    previous_output: *prev,
                    sequence: csv_value,
                    ..Default::default()
                })
            } else {
                return Err(RevaultError::TransactionCreation(format!(
                    "Spend: prevout ({:?}) type mismatch",
                    prevout
                )));
            }
        }

        let mut txouts = Vec::<TxOut>::with_capacity(outputs.len());
        for out in outputs {
            match out {
                RevaultTxOut::SpendTxOut(ref txout) | RevaultTxOut::VaultTxOut(ref txout) => {
                    txouts.push(txout.clone())
                }
                _ => {
                    return Err(RevaultError::TransactionCreation(format!(
                        "Spend: output ({:?}) type mismatch",
                        out
                    )))
                }
            }
        }

        Ok(RevaultTransaction::SpendTransaction(Transaction {
            version: 2,
            lock_time: 0,
            input: txins,
            output: txouts,
        }))
    }

    /// Create a new cancel transaction.
    /// A cancel transaction always pays to a vault output and spend the unvault output, and
    /// may have a fee-bumping input.
    pub fn new_cancel(
        prevouts: &[RevaultPrevout],
        txouts: &[RevaultTxOut],
    ) -> Result<RevaultTransaction, RevaultError> {
        match (prevouts, txouts) {
            // FIXME: Use https://github.com/rust-lang/rust/issues/54883 once stabilized ..
            (
                &[RevaultPrevout::UnvaultPrevout(_)],
                &[RevaultTxOut::VaultTxOut(ref vault_txout)],
            )
            | (
                &[RevaultPrevout::UnvaultPrevout(_), RevaultPrevout::WalletPrevout(_)],
                &[RevaultTxOut::VaultTxOut(ref vault_txout)],
            ) => {
                let inputs = prevouts
                    .iter()
                    .map(|prevout| TxIn {
                        previous_output: match prevout {
                            RevaultPrevout::UnvaultPrevout(ref prev)
                            | RevaultPrevout::WalletPrevout(ref prev) => *prev,
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
                "Cancel: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                prevouts, txouts,
            ))),
        }
    }

    /// Create an emergency transaction.
    /// There are two emergency transactions, one spending the vault output and one spending
    /// the unvault output. Both may have a fee-bumping input.
    pub fn new_emergency(
        prevouts: &[RevaultPrevout],
        txouts: &[RevaultTxOut],
    ) -> Result<RevaultTransaction, RevaultError> {
        // FIXME: Use https://github.com/rust-lang/rust/issues/54883 once stabilized ..
        match (prevouts, txouts) {
            (
                &[RevaultPrevout::VaultPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            )
            | (
                &[RevaultPrevout::VaultPrevout(_), RevaultPrevout::WalletPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            )
            | (
                &[RevaultPrevout::UnvaultPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            )
            | (
                &[RevaultPrevout::UnvaultPrevout(_), RevaultPrevout::WalletPrevout(_)],
                &[RevaultTxOut::EmergencyTxOut(ref emer_txout)],
            ) => {
                let inputs = prevouts
                    .iter()
                    .map(|prevout| TxIn {
                        previous_output: match prevout {
                            RevaultPrevout::VaultPrevout(ref prev)
                            | RevaultPrevout::UnvaultPrevout(ref prev)
                            | RevaultPrevout::WalletPrevout(ref prev) => *prev,
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
                "Emergency: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                prevouts, txouts,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RevaultError, RevaultPrevout, RevaultTransaction, RevaultTxOut, RBF_SEQUENCE};

    use std::str::FromStr;

    use bitcoin::{OutPoint, Transaction, TxIn, TxOut};

    #[test]
    fn test_transaction_creation() {
        // Transactions which happened to be in my mempool
        let outpoint = OutPoint::from_str(
            "ea4a9f84cce4e5b195b496e2823f7939b474f3fd3d2d8d59b91bb2312a8113f3:0",
        )
        .unwrap();
        let feebump_outpoint = OutPoint::from_str(
            "1d239c9299a7e350e3ae6e5fb4068f13b4e01fe188a0d0533f6555aad6b17b0a:0",
        )
        .unwrap();

        let vault_prevout = RevaultPrevout::VaultPrevout(outpoint);
        let unvault_prevout = RevaultPrevout::UnvaultPrevout(outpoint);
        let feebump_prevout = RevaultPrevout::WalletPrevout(feebump_outpoint);

        let txout = TxOut {
            value: 18,
            ..TxOut::default()
        };
        let unvault_txout = RevaultTxOut::UnvaultTxOut(txout.clone());
        let feebump_txout = RevaultTxOut::CpfpTxOut(txout.clone());
        let spend_txout = RevaultTxOut::SpendTxOut(txout.clone());
        let vault_txout = RevaultTxOut::VaultTxOut(txout.clone());
        let emer_txout = RevaultTxOut::EmergencyTxOut(txout.clone());

        // =======================
        // The unvault transaction
        assert_eq!(
            RevaultTransaction::new_unvault(
                &[vault_prevout],
                &[unvault_txout.clone(), feebump_txout.clone()]
            ),
            Ok(RevaultTransaction::UnvaultTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: outpoint,
                    ..TxIn::default()
                }],
                output: vec![txout.clone(), txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_unvault(
                &[vault_prevout],
                &[vault_txout.clone(), feebump_txout.clone()]
            ),
            Err(RevaultError::TransactionCreation(format!(
                "Unvault: type mismatch on prevout ({:?}) or output(s) ({:?})",
                &[vault_prevout],
                &[vault_txout.clone(), feebump_txout.clone()]
            )))
        );

        // =====================
        // The spend transaction
        assert_eq!(
            RevaultTransaction::new_spend(&[unvault_prevout], &[spend_txout.clone()], 22),
            Ok(RevaultTransaction::SpendTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: outpoint,
                    sequence: 22,
                    ..TxIn::default()
                }],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_spend(&[vault_prevout], &[spend_txout.clone()], 144),
            Err(RevaultError::TransactionCreation(format!(
                "Spend: prevout ({:?}) type mismatch",
                vault_prevout,
            )))
        );
        // multiple inputs
        assert_eq!(
            RevaultTransaction::new_spend(
                &[unvault_prevout, unvault_prevout],
                &[spend_txout.clone()],
                9
            ),
            Ok(RevaultTransaction::SpendTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![
                    TxIn {
                        previous_output: outpoint,
                        sequence: 9,
                        ..TxIn::default()
                    },
                    TxIn {
                        previous_output: outpoint,
                        sequence: 9,
                        ..TxIn::default()
                    }
                ],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_spend(
                &[unvault_prevout, feebump_prevout],
                &[spend_txout.clone()],
                144
            ),
            Err(RevaultError::TransactionCreation(format!(
                "Spend: prevout ({:?}) type mismatch",
                feebump_prevout,
            )))
        );

        // multiple outputs
        assert_eq!(
            RevaultTransaction::new_spend(
                &[unvault_prevout],
                &[spend_txout.clone(), spend_txout.clone()],
                24
            ),
            Ok(RevaultTransaction::SpendTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: outpoint,
                    sequence: 24,
                    ..TxIn::default()
                }],
                output: vec![txout.clone(), txout.clone()]
            }))
        );

        // Both (with one output being change)
        assert_eq!(
            RevaultTransaction::new_spend(
                &[unvault_prevout, unvault_prevout],
                &[spend_txout.clone(), vault_txout.clone()],
                24
            ),
            Ok(RevaultTransaction::SpendTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![
                    TxIn {
                        previous_output: outpoint,
                        sequence: 24,
                        ..TxIn::default()
                    },
                    TxIn {
                        previous_output: outpoint,
                        sequence: 24,
                        ..TxIn::default()
                    }
                ],
                output: vec![txout.clone(), txout.clone()]
            }))
        );

        // =====================
        // The cancel transaction
        // Without feebump
        assert_eq!(
            RevaultTransaction::new_cancel(&[unvault_prevout], &[vault_txout.clone()]),
            Ok(RevaultTransaction::CancelTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: outpoint,
                    sequence: RBF_SEQUENCE,
                    ..TxIn::default()
                }],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_cancel(
                &[unvault_prevout],
                &[vault_txout.clone(), vault_txout.clone()]
            ),
            Err(RevaultError::TransactionCreation(format!(
                "Cancel: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                &[unvault_prevout],
                &[vault_txout.clone(), vault_txout.clone()]
            )))
        );

        // With feebump
        assert_eq!(
            RevaultTransaction::new_cancel(
                &[unvault_prevout, feebump_prevout],
                &[vault_txout.clone()],
            ),
            Ok(RevaultTransaction::CancelTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![
                    TxIn {
                        previous_output: outpoint,
                        sequence: RBF_SEQUENCE,
                        ..TxIn::default()
                    },
                    TxIn {
                        previous_output: feebump_outpoint,
                        sequence: RBF_SEQUENCE,
                        ..TxIn::default()
                    }
                ],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_cancel(
                &[unvault_prevout, feebump_prevout],
                &[vault_txout.clone(), vault_txout.clone()]
            ),
            Err(RevaultError::TransactionCreation(format!(
                "Cancel: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                &[unvault_prevout, feebump_prevout],
                &[vault_txout.clone(), vault_txout.clone()]
            )))
        );

        // =====================
        // The emergency transactions
        // Vault emergency, without feebump
        assert_eq!(
            RevaultTransaction::new_emergency(&[vault_prevout], &[emer_txout.clone()]),
            Ok(RevaultTransaction::EmergencyTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: outpoint,
                    sequence: RBF_SEQUENCE,
                    ..TxIn::default()
                }],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_emergency(&[vault_prevout], &[vault_txout.clone()]),
            Err(RevaultError::TransactionCreation(format!(
                "Emergency: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                &[vault_prevout],
                &[vault_txout.clone()]
            )))
        );

        // Vault emergency, with feebump
        assert_eq!(
            RevaultTransaction::new_emergency(
                &[vault_prevout, feebump_prevout],
                &[emer_txout.clone()],
            ),
            Ok(RevaultTransaction::EmergencyTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![
                    TxIn {
                        previous_output: outpoint,
                        sequence: RBF_SEQUENCE,
                        ..TxIn::default()
                    },
                    TxIn {
                        previous_output: feebump_outpoint,
                        sequence: RBF_SEQUENCE,
                        ..TxIn::default()
                    }
                ],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_emergency(
                &[vault_prevout, vault_prevout],
                &[emer_txout.clone()]
            ),
            Err(RevaultError::TransactionCreation(format!(
                "Emergency: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                &[vault_prevout, vault_prevout],
                &[emer_txout.clone()]
            )))
        );

        // Unvault emergency, without feebump
        assert_eq!(
            RevaultTransaction::new_emergency(&[unvault_prevout], &[emer_txout.clone()]),
            Ok(RevaultTransaction::EmergencyTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: outpoint,
                    sequence: RBF_SEQUENCE,
                    ..TxIn::default()
                }],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_emergency(&[unvault_prevout], &[spend_txout.clone()]),
            Err(RevaultError::TransactionCreation(format!(
                "Emergency: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                &[unvault_prevout],
                &[spend_txout.clone()]
            )))
        );

        // Unvault emergency, with feebump
        assert_eq!(
            RevaultTransaction::new_emergency(
                &[unvault_prevout, feebump_prevout],
                &[emer_txout.clone()],
            ),
            Ok(RevaultTransaction::EmergencyTransaction(Transaction {
                version: 2,
                lock_time: 0,
                input: vec![
                    TxIn {
                        previous_output: outpoint,
                        sequence: RBF_SEQUENCE,
                        ..TxIn::default()
                    },
                    TxIn {
                        previous_output: feebump_outpoint,
                        sequence: RBF_SEQUENCE,
                        ..TxIn::default()
                    }
                ],
                output: vec![txout.clone()]
            }))
        );
        assert_eq!(
            RevaultTransaction::new_emergency(
                &[unvault_prevout, vault_prevout],
                &[emer_txout.clone()]
            ),
            Err(RevaultError::TransactionCreation(format!(
                "Emergency: prevout(s) ({:?}) or output(s) ({:?}) type mismatch",
                &[unvault_prevout, vault_prevout],
                &[emer_txout.clone()]
            )))
        );
    }
}
