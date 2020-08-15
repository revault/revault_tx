mod revault_error;
mod scripts;
mod transations;

pub use revault_error::RevaultError;
pub use scripts::{get_default_unvault_descriptors, get_default_vault_descriptors};
pub use transations::{RevaultPrevout, RevaultSatisfier, RevaultTransaction, RevaultTxOut};

#[cfg(test)]
mod tests {
    use super::{
        get_default_unvault_descriptors, get_default_vault_descriptors, RevaultError,
        RevaultPrevout, RevaultSatisfier, RevaultTransaction, RevaultTxOut,
    };

    use bitcoin::{OutPoint, PublicKey, Transaction, TxIn, TxOut};

    use rand::RngCore;
    use std::str::FromStr;

    fn get_random_privkey() -> secp256k1::SecretKey {
        let mut rand_bytes = [0u8; 32];
        let mut secret_key = Err(secp256k1::Error::InvalidSecretKey);

        while secret_key.is_err() {
            rand::thread_rng().fill_bytes(&mut rand_bytes);
            secret_key = secp256k1::SecretKey::from_slice(&rand_bytes);
        }

        secret_key.unwrap()
    }

    // A sanity check for standard usage
    #[test]
    fn test_transaction_chain() {
        let secp = secp256k1::Secp256k1::new();

        // Generate some private key pairs for every participant
        let managers_priv = (0..3)
            .map(|_| get_random_privkey())
            .collect::<Vec<secp256k1::SecretKey>>();
        let managers = managers_priv
            .iter()
            .map(|privkey| PublicKey {
                compressed: true,
                key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
            })
            .collect::<Vec<PublicKey>>();
        let non_managers_priv = (0..8)
            .map(|_| get_random_privkey())
            .collect::<Vec<secp256k1::SecretKey>>();
        let non_managers = non_managers_priv
            .iter()
            .map(|privkey| PublicKey {
                compressed: true,
                key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
            })
            .collect::<Vec<PublicKey>>();
        let cosigners_priv = (0..8)
            .map(|_| get_random_privkey())
            .collect::<Vec<secp256k1::SecretKey>>();
        let cosigners = cosigners_priv
            .iter()
            .map(|privkey| PublicKey {
                compressed: true,
                key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
            })
            .collect::<Vec<PublicKey>>();
        let all_participants_priv = managers_priv
            .iter()
            .chain(non_managers_priv.iter())
            .cloned()
            .collect::<Vec<secp256k1::SecretKey>>();

        // The two interesting outputs, which Scripts are "hard" to satisfy generalistically
        const CSV_VALUE: u32 = 42;
        let unvault_descriptor =
            get_default_unvault_descriptors(&non_managers, &managers, &cosigners, CSV_VALUE)
                .expect("Unvault descriptor generation error");
        let vault_descriptor = get_default_vault_descriptors(
            &managers
                .into_iter()
                .chain(non_managers.into_iter())
                .collect::<Vec<PublicKey>>(),
        )
        .expect("Vault descriptor generation error");

        // The funding transaction does not matter (random txid from my mempool)
        let vault_scriptpubkey = vault_descriptor.script_pubkey();
        let vault_tx = RevaultTransaction::VaultTransaction(Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::from_str(
                    "39a8212c6a9b467680d43e47b61b8363fe1febb761f9f548eb4a432b2bc9bbec:0",
                )
                .unwrap(),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: 1,
                script_pubkey: vault_scriptpubkey.clone(),
            }],
        });
        let vault_prevout = RevaultPrevout::VaultPrevout(vault_tx.prevout(0));

        // Create and sign the first (vault) emergency transaction
        let emer_txo = RevaultTxOut::EmergencyTxOut(TxOut {
            value: 1,
            ..TxOut::default()
        });
        let mut emergency_tx =
            RevaultTransaction::new_emergency(&[vault_prevout], &[emer_txo.clone()])
                .expect("Vault emergency transaction creation falure");
        let emergency_tx_sighash = emergency_tx.signature_hash(0, &vault_scriptpubkey, true);
        let mut revault_sat = RevaultSatisfier::new(&mut emergency_tx, 0, &vault_descriptor)
            .expect("Creating satisfier.");
        all_participants_priv.iter().for_each(|privkey| {
            revault_sat.insert_sig(
                PublicKey {
                    compressed: true,
                    key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
                },
                secp.sign(
                    &secp256k1::Message::from_slice(&emergency_tx_sighash).unwrap(),
                    &privkey,
                ),
                true,
            );
        });
        revault_sat
            .satisfy()
            .expect("Satisfying emergency transaction");

        // Create but *do not sign* the unvaulting transaction until all revaulting transactions
        // are
        let unvault_scriptpubkey = unvault_descriptor.script_pubkey();
        let unvault_txo = RevaultTxOut::UnvaultTxOut(TxOut {
            value: 1,
            script_pubkey: unvault_scriptpubkey.clone(),
        });
        let cpfp_txo = RevaultTxOut::CpfpTxOut(TxOut {
            value: 1,
            ..TxOut::default()
        });
        let mut unvault_tx =
            RevaultTransaction::new_unvault(&[vault_prevout], &[unvault_txo, cpfp_txo])
                .expect("Unvault transaction creation failure");

        // Create and sign the cancel transaction
        let unvault_prevout = RevaultPrevout::UnvaultPrevout(unvault_tx.prevout(0));
        let revault_txo = RevaultTxOut::VaultTxOut(TxOut {
            value: 1,
            script_pubkey: vault_descriptor.script_pubkey(),
        });
        let mut cancel_tx = RevaultTransaction::new_cancel(&[unvault_prevout], &[revault_txo])
            .expect("Cancel transaction creation failure");
        let cancel_tx_sighash = cancel_tx.signature_hash(0, &unvault_scriptpubkey, true);
        let mut revault_sat: RevaultSatisfier<PublicKey> =
            RevaultSatisfier::<PublicKey>::new(&mut cancel_tx, 0, &unvault_descriptor)
                .expect("Creating satisfier.");
        all_participants_priv.iter().for_each(|privkey| {
            revault_sat.insert_sig(
                PublicKey {
                    compressed: true,
                    key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
                },
                secp.sign(
                    &secp256k1::Message::from_slice(&cancel_tx_sighash).unwrap(),
                    &privkey,
                ),
                true,
            );
        });
        revault_sat
            .satisfy()
            .expect("Satisfying cancel transaction");

        // Create and sign the second (unvault) emergency transaction
        let mut unemergency_tx = RevaultTransaction::new_emergency(&[unvault_prevout], &[emer_txo])
            .expect("Unvault emergency transaction creation failure");
        let unemergency_tx_sighash = unemergency_tx.signature_hash(0, &unvault_scriptpubkey, true);
        revault_sat =
            RevaultSatisfier::<PublicKey>::new(&mut unemergency_tx, 0, &unvault_descriptor)
                .expect("Creating satisfier.");
        all_participants_priv.iter().for_each(|privkey| {
            revault_sat.insert_sig(
                PublicKey {
                    compressed: true,
                    key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
                },
                secp.sign(
                    &secp256k1::Message::from_slice(&unemergency_tx_sighash).unwrap(),
                    &privkey,
                ),
                true,
            );
        });
        revault_sat
            .satisfy()
            .expect("Satisfying unvault emergency transaction");

        // Now we can sign the unvault
        let unvault_tx_sighash = unvault_tx.signature_hash(0, &vault_scriptpubkey, false);
        revault_sat = RevaultSatisfier::<PublicKey>::new(&mut unvault_tx, 0, &unvault_descriptor)
            .expect("Creating satisfier.");
        all_participants_priv.iter().for_each(|privkey| {
            revault_sat.insert_sig(
                PublicKey {
                    compressed: true,
                    key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
                },
                secp.sign(
                    &secp256k1::Message::from_slice(&unvault_tx_sighash).unwrap(),
                    &privkey,
                ),
                false,
            );
        });
        revault_sat
            .satisfy()
            .expect("Satisfying unvault transaction");

        let spend_txo = RevaultTxOut::SpendTxOut(TxOut {
            value: 1,
            ..TxOut::default()
        });
        // Test satisfaction failure with a wrong CSV value
        {
            let mut spend_tx = RevaultTransaction::new_spend(
                &[unvault_prevout],
                &[spend_txo.clone()],
                CSV_VALUE - 1,
            )
            .expect("Spend transaction (n.1) creation failure");
            let spend_tx_sighash = spend_tx.signature_hash(0, &unvault_scriptpubkey, false);
            let mut tmp_revault_sat =
                RevaultSatisfier::<PublicKey>::new(&mut spend_tx, 0, &unvault_descriptor)
                    .expect("Creating satisfier.");
            // Only the managers + automated cosigners are required
            managers_priv
                .iter()
                .chain(cosigners_priv.iter())
                .for_each(|privkey| {
                    tmp_revault_sat.insert_sig(
                        PublicKey {
                            compressed: true,
                            key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
                        },
                        secp.sign(
                            &secp256k1::Message::from_slice(&spend_tx_sighash).unwrap(),
                            &privkey,
                        ),
                        false,
                    );
                });
            assert_eq!(
                tmp_revault_sat.satisfy(),
                Err(RevaultError::InputSatisfaction(
                    "Script satisfaction error: could not satisfy.".to_string()
                ))
            );
        }

        // "This time for sure !"
        let mut spend_tx =
            RevaultTransaction::new_spend(&[unvault_prevout], &[spend_txo], CSV_VALUE)
                .expect("Spend transaction (n.2) creation failure");
        let spend_tx_sighash = spend_tx.signature_hash(0, &unvault_scriptpubkey, false);
        revault_sat = RevaultSatisfier::<PublicKey>::new(&mut spend_tx, 0, &unvault_descriptor)
            .expect("Creating satisfier.");
        // Only the managers + automated cosigners are required
        managers_priv
            .iter()
            .chain(cosigners_priv.iter())
            .for_each(|privkey| {
                revault_sat.insert_sig(
                    PublicKey {
                        compressed: true,
                        key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
                    },
                    secp.sign(
                        &secp256k1::Message::from_slice(&spend_tx_sighash).unwrap(),
                        &privkey,
                    ),
                    false,
                );
            });
        revault_sat
            .satisfy()
            .expect("Satisfying the valid spend tx");
    }
}
