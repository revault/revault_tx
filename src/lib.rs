mod revault_error;
mod scripts;
mod transations;

pub use scripts::{get_default_unvault_descriptors, get_default_vault_descriptors};
pub use transations::{RevaultPrevout, RevaultTransaction, RevaultTxOut};

#[cfg(test)]
mod tests {
    use super::{
        get_default_unvault_descriptors, get_default_vault_descriptors, RevaultPrevout,
        RevaultTransaction, RevaultTxOut,
    };

    use bitcoin::{OutPoint, PublicKey, TxOut};

    use rand::RngCore;

    fn get_random_pubkey() -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let mut rand_bytes = [0u8; 32];
        // Make rustc happy..
        let mut secret_key = Err(secp256k1::Error::InvalidSecretKey);

        while secret_key.is_err() {
            rand::thread_rng().fill_bytes(&mut rand_bytes);
            secret_key = secp256k1::SecretKey::from_slice(&rand_bytes);
        }

        PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key.unwrap()),
        }
    }

    // A sanity check for standard usage
    #[test]
    fn test_transaction_chain() {
        let managers = (0..3)
            .map(|_| get_random_pubkey())
            .collect::<Vec<PublicKey>>();
        let non_managers = (0..8)
            .map(|_| get_random_pubkey())
            .collect::<Vec<PublicKey>>();
        let cosigners = (0..8)
            .map(|_| get_random_pubkey())
            .collect::<Vec<PublicKey>>();
        let unvault_descriptor =
            get_default_unvault_descriptors(&non_managers, &managers, &cosigners, 42)
                .expect("Unvault descriptor generation error");
        let vault_descriptor = get_default_vault_descriptors(
            &managers
                .into_iter()
                .chain(non_managers.into_iter())
                .collect(),
        )
        .expect("Vault descriptor generation error");

        let vault_txo = RevaultTxOut::VaultTxOut(TxOut {
            value: 1,
            script_pubkey: vault_descriptor.script_pubkey(),
        });
        let vault_prevout = RevaultPrevout::VaultPrevout(OutPoint {
            ..OutPoint::default()
        });

        let emer_txo = RevaultTxOut::EmergencyTxOut(TxOut {
            value: 1,
            ..TxOut::default()
        });
        let _emergency_tx =
            RevaultTransaction::new_emergency(&[vault_prevout], &[emer_txo.clone()])
                .expect("Vault emergency transaction creation falure");

        let unvault_txo = RevaultTxOut::UnvaultTxOut(TxOut {
            value: 1,
            script_pubkey: unvault_descriptor.script_pubkey(),
        });
        let cpfp_txo = RevaultTxOut::CpfpTxOut(TxOut {
            value: 1,
            ..TxOut::default()
        });
        let unvault_tx =
            RevaultTransaction::new_unvault(&[vault_prevout], &[unvault_txo, cpfp_txo])
                .expect("Unvault transaction creation failure");

        let unvault_prevout = match unvault_tx {
            RevaultTransaction::UnvaultTransaction(ref tx) => {
                RevaultPrevout::UnvaultPrevout(OutPoint {
                    txid: tx.txid(),
                    vout: 0,
                })
            }
            _ => unreachable!(),
        };
        let _cancel_tx = RevaultTransaction::new_cancel(&[unvault_prevout], &[vault_txo])
            .expect("Cancel transaction creation failure");

        let _unvault_emergency_tx =
            RevaultTransaction::new_emergency(&[unvault_prevout], &[emer_txo])
                .expect("Unvault emergency transaction creation failure");

        let spend_txo = RevaultTxOut::SpendTxOut(TxOut {
            value: 1,
            ..TxOut::default()
        });
        let _spend_tx = RevaultTransaction::new_spend(&[unvault_prevout], &[spend_txo], 19)
            .expect("Spend transaction creation failure");
    }
}
