//! Revault transactions
//!
//! Typesafe routines to create bare revault transactions.

use crate::{error::Error, prevouts::*, txouts::*};

use bitcoin::consensus::encode;
use bitcoin::consensus::encode::Encodable;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::{OutPoint, PublicKey, Script, SigHash, SigHashType, Transaction, TxIn, TxOut};
use miniscript::{BitcoinSig, Descriptor, MiniscriptKey, Satisfier, ToPublicKey};
use secp256k1::Signature;

use std::collections::HashMap;
use std::fmt;

/// TxIn's sequence to set for the tx to be bip125-replaceable
pub const RBF_SEQUENCE: u32 = u32::MAX - 2;

/// A Revault transaction. Apart from the VaultTransaction, all variants must be instanciated
/// using the new_*() methods.
pub trait RevaultTransaction: fmt::Debug {
    /// Get the inner transaction
    fn inner_tx(&self) -> &Transaction;

    /// Get the inner transaction
    fn inner_tx_mut(&mut self) -> &mut Transaction;

    /// Get the specified output of this transaction as an OutPoint to be referenced
    /// in a following transaction.
    fn into_prevout(&self, vout: u32) -> OutPoint {
        OutPoint {
            txid: self.inner_tx().txid(),
            vout,
        }
    }

    /// Get the network-serialized (inner) transaction
    fn serialize(&self) -> Vec<u8> {
        // FIXME: this panics...
        encode::serialize(self.inner_tx())
    }

    /// Get the hexadecimal representation of the transaction as used by the bitcoind API.
    ///
    /// # Errors
    /// - If we could not encode the transaction (should not happen).
    fn hex(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut buff = Vec::<u8>::new();
        let mut as_hex = String::new();

        self.inner_tx().consensus_encode(&mut buff)?;
        for byte in buff.into_iter() {
            as_hex.push_str(&format!("{:02x}", byte));
        }

        Ok(as_hex)
    }
}

// Boilerplate for newtype declaration and small trait helpers implementation.
macro_rules! impl_revault_transaction {
    ( $transaction_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug)]
        pub struct $transaction_name(Transaction);

        impl RevaultTransaction for $transaction_name {
            fn inner_tx(&self) -> &Transaction {
                &self.0
            }

            fn inner_tx_mut(&mut self) -> &mut Transaction {
                &mut self.0
            }
        }
    };
}

// Boilerplate for creating an actual (inner) transaction with a known number of prevouts / txouts.
macro_rules! create_tx {
    ( [$( ($prevout:expr, $sequence:expr) ),* $(,)?], [$($txout:expr),* $(,)?]) => {
        Transaction {
            version: 2,
            lock_time: 0, // FIXME: anti fee-snipping
            input: vec![$(
                TxIn {
                    previous_output: $prevout.outpoint(),
                    sequence: $sequence,
                    ..TxIn::default()
                },
            )*],
            output: vec![$(
                $txout.get_txout(),
            )*],
        }
    }
}

impl_revault_transaction!(
    UnvaultTransaction,
    doc = "The unvaulting transaction, spending a vault and being eventually spent by a spend transaction (if not revaulted)."
);
impl UnvaultTransaction {
    /// An unvault transaction always spends one vault output and contains one CPFP output in
    /// addition to the unvault one.
    pub fn new(
        vault_input: (VaultPrevout, u32),
        unvault_txout: UnvaultTxOut,
        cpfp_txout: CpfpTxOut,
    ) -> UnvaultTransaction {
        UnvaultTransaction(create_tx!(
            [(vault_input.0, vault_input.1)],
            [unvault_txout, cpfp_txout]
        ))
    }
}

impl_revault_transaction!(
    CancelTransaction,
    doc = "The transaction \"revaulting\" a spend attempt, i.e. spending the unvaulting transaction back to a vault txo."
);
impl CancelTransaction {
    /// A cancel transaction always pays to a vault output and spends the unvault output, and
    /// may have a fee-bumping input.
    pub fn new(
        unvault_input: (UnvaultPrevout, u32),
        feebump_input: Option<(FeeBumpPrevout, u32)>,
        vault_txout: VaultTxOut,
    ) -> CancelTransaction {
        CancelTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!(
                [
                    (unvault_input.0, unvault_input.1),
                    (feebump_input.0, feebump_input.1)
                ],
                [vault_txout]
            )
        } else {
            create_tx!([(unvault_input.0, unvault_input.1)], [vault_txout])
        })
    }
}

impl_revault_transaction!(
    EmergencyTransaction,
    doc = "The transaction spending a vault output to The Emergency Script."
);
impl EmergencyTransaction {
    /// The first emergency transaction always spends a vault output and pays to the Emergency
    /// Script. It may also spend an additional output for fee-bumping.
    pub fn new(
        vault_input: (VaultPrevout, u32),
        feebump_input: Option<(FeeBumpPrevout, u32)>,
        emer_txout: EmergencyTxOut,
    ) -> EmergencyTransaction {
        EmergencyTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!(
                [
                    (vault_input.0, vault_input.1),
                    (feebump_input.0, feebump_input.1)
                ],
                [emer_txout]
            )
        } else {
            create_tx!([(vault_input.0, vault_input.1)], [emer_txout])
        })
    }
}

impl_revault_transaction!(
    UnvaultEmergencyTransaction,
    doc = "The transaction spending an unvault output to The Emergency Script."
);
impl UnvaultEmergencyTransaction {
    /// The second emergency transaction always spends an unvault output and pays to the Emergency
    /// Script. It may also spend an additional output for fee-bumping.
    pub fn new(
        unvault_input: (UnvaultPrevout, u32),
        feebump_input: Option<(FeeBumpPrevout, u32)>,
        emer_txout: EmergencyTxOut,
    ) -> UnvaultEmergencyTransaction {
        UnvaultEmergencyTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!(
                [
                    (unvault_input.0, unvault_input.1),
                    (feebump_input.0, feebump_input.1)
                ],
                [emer_txout]
            )
        } else {
            create_tx!([(unvault_input.0, unvault_input.1)], [emer_txout])
        })
    }
}

impl_revault_transaction!(
    SpendTransaction,
    doc = "The transaction spending the unvaulting transaction, paying to one or multiple \
    externally-controlled addresses, and possibly to a new vault txo for the change."
);
impl SpendTransaction {
    /// A spend transaction can batch multiple unvault txouts, and may have any number of
    /// txouts (including, but not restricted to, change).
    pub fn new(
        unvault_inputs: &[(UnvaultPrevout, u32)],
        spend_txouts: Vec<SpendTxOut>,
    ) -> SpendTransaction {
        SpendTransaction(Transaction {
            version: 2,
            lock_time: 0, // FIXME: anti fee-snipping
            input: unvault_inputs
                .iter()
                .map(|input| TxIn {
                    previous_output: input.0.outpoint(),
                    sequence: input.1,
                    ..TxIn::default()
                })
                .collect(),
            output: spend_txouts
                .into_iter()
                .map(|spend_txout| match spend_txout {
                    SpendTxOut::Destination(txo) => txo.get_txout(),
                    SpendTxOut::Change(txo) => txo.get_txout(),
                })
                .collect(),
        })
    }
}

impl_revault_transaction!(
    VaultTransaction,
    doc = "The funding transaction, we don't create it but it's a handy wrapper for verify()."
);
impl VaultTransaction {
    /// We don't create nor are able to sign, it's just a type wrapper for verify so explicitly no
    /// restriction on the types here
    pub fn new(tx: Transaction) -> VaultTransaction {
        VaultTransaction(tx)
    }
}

impl_revault_transaction!(
    FeeBumpTransaction,
    doc = "The fee-bumping transaction, we don't create it but it may be passed to verify()."
);
impl FeeBumpTransaction {
    /// We don't create nor are able to sign, it's just a type wrapper for verify so explicitly no
    /// restriction on the types here
    pub fn new(tx: Transaction) -> FeeBumpTransaction {
        FeeBumpTransaction(tx)
    }
}

// Non typesafe sighash boilerplate
fn sighash(
    tx: &Transaction,
    input_index: usize,
    previous_txout: &TxOut,
    script_code: &Script,
    is_anyonecanpay: bool,
) -> SigHash {
    // FIXME: cache the cache for when the user has too much cash
    let mut cache = SigHashCache::new(&tx);
    cache.signature_hash(
        input_index,
        &script_code,
        previous_txout.value,
        if is_anyonecanpay {
            SigHashType::AllPlusAnyoneCanPay
        } else {
            SigHashType::All
        },
    )
}

// We use this to configure which txouts types are valid to be used by a given transaction type.
// This allows to compile-time check that we request a sighash for what is more likely to be a
// valid Revault transaction.
macro_rules! impl_valid_prev_txouts {
    ( $valid_prev_txouts: ident, [$($txout:ident),*], $doc_comment:meta ) => {
        #[$doc_comment]
        pub trait $valid_prev_txouts: RevaultTxOut {}
        $(impl $valid_prev_txouts for $txout {})*
    };
}

impl UnvaultTransaction {
    /// Get a signature hash for an input, previous_txout's type is statically checked to be
    /// acceptable.
    pub fn signature_hash(
        &self,
        input_index: usize,
        previous_txout: &VaultTxOut,
        script_code: &Script,
    ) -> SigHash {
        sighash(
            &self.0,
            input_index,
            previous_txout.inner_txout(),
            script_code,
            false,
        )
    }
}

impl_valid_prev_txouts!(
    CancelPrevTxout,
    [UnvaultTxOut, FeeBumpTxOut],
    doc = "CancelTransaction can only spend UnvaultTxOut and FeeBumpTxOut txouts"
);
impl CancelTransaction {
    /// Get a signature hash for an input, previous_txout's type is statically checked to be
    /// acceptable.
    pub fn signature_hash(
        &self,
        input_index: usize,
        previous_txout: &impl CancelPrevTxout,
        script_code: &Script,
        is_anyonecanpay: bool,
    ) -> SigHash {
        sighash(
            &self.0,
            input_index,
            previous_txout.inner_txout(),
            script_code,
            is_anyonecanpay,
        )
    }
}

impl_valid_prev_txouts!(
    EmergencyPrevTxout,
    [VaultTxOut, FeeBumpTxOut],
    doc = "EmergencyTransaction can only spend UnvaultTxOut and FeeBumpTxOut txouts"
);
impl EmergencyTransaction {
    /// Get a signature hash for an input, previous_txout's type is statically checked to be
    /// acceptable.
    pub fn signature_hash(
        &self,
        input_index: usize,
        previous_txout: &impl EmergencyPrevTxout,
        script_code: &Script,
        is_anyonecanpay: bool,
    ) -> SigHash {
        sighash(
            &self.0,
            input_index,
            previous_txout.inner_txout(),
            script_code,
            is_anyonecanpay,
        )
    }
}

impl_valid_prev_txouts!(
    UnvaultEmerPrevTxout,
    [UnvaultTxOut, FeeBumpTxOut],
    doc = "UnvaultEmergencyTransaction can only spend UnvaultTxOut and FeeBumpTxOut txouts."
);
impl UnvaultEmergencyTransaction {
    /// Get a signature hash for an input, previous_txout's type is statically checked to be
    /// acceptable.
    fn signature_hash(
        &self,
        input_index: usize,
        previous_txout: &impl UnvaultEmerPrevTxout,
        script_code: &Script,
        is_anyonecanpay: bool,
    ) -> SigHash {
        sighash(
            &self.0,
            input_index,
            previous_txout.inner_txout(),
            script_code,
            is_anyonecanpay,
        )
    }
}

impl SpendTransaction {
    /// Get a signature hash for an input, previous_txout's type is statically checked to be
    /// acceptable.
    pub fn signature_hash(
        &self,
        input_index: usize,
        previous_txout: &UnvaultTxOut,
        script_code: &Script,
    ) -> SigHash {
        sighash(
            &self.0,
            input_index,
            previous_txout.inner_txout(),
            script_code,
            false,
        )
    }
}

/// A small wrapper around what is needed to implement the Satisfier trait for Revault
/// transactions.
struct RevaultInputSatisfier<Pk: MiniscriptKey> {
    pkhashmap: HashMap<Pk::Hash, Pk>,
    sigmap: HashMap<Pk, BitcoinSig>,
    sequence: u32,
}

impl<Pk: MiniscriptKey + ToPublicKey> RevaultInputSatisfier<Pk> {
    fn new(sequence: u32) -> RevaultInputSatisfier<Pk> {
        RevaultInputSatisfier::<Pk> {
            sequence,
            pkhashmap: HashMap::<Pk::Hash, Pk>::new(),
            sigmap: HashMap::<Pk, BitcoinSig>::new(),
        }
    }

    fn insert_sig(
        &mut self,
        pubkey: Pk,
        sig: Signature,
        is_anyonecanpay: bool,
    ) -> Option<BitcoinSig> {
        self.pkhashmap
            .insert(pubkey.to_pubkeyhash(), pubkey.clone());
        self.sigmap.insert(
            pubkey,
            (
                sig,
                if is_anyonecanpay {
                    SigHashType::AllPlusAnyoneCanPay
                } else {
                    SigHashType::All
                },
            ),
        )
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for RevaultInputSatisfier<Pk> {
    fn lookup_sig(&self, key: &Pk) -> Option<BitcoinSig> {
        self.sigmap.get(key).copied()
    }

    // The policy compiler will often optimize the Script to use pkH, so we need this method to be
    // implemented *both* for satisfaction and disatisfaction !
    fn lookup_pkh_sig(&self, keyhash: &Pk::Hash) -> Option<(PublicKey, BitcoinSig)> {
        if let Some(key) = self.pkhashmap.get(keyhash) {
            if let Some((sig, sig_type)) = self.lookup_sig(key) {
                return Some((key.to_public_key(), (sig, sig_type)));
            }
        }
        None
    }

    fn check_older(&self, csv: u32) -> bool {
        assert!((csv & (1 << 22) == 0));
        self.sequence >= csv
    }
}

/// A wrapper handling the satisfaction of a RevaultTransaction input given the input's index
/// and the previous output's script descriptor.
pub struct RevaultSatisfier<'a, Pk: MiniscriptKey + ToPublicKey> {
    txin: &'a mut TxIn,
    descriptor: &'a Descriptor<Pk>,
    satisfier: RevaultInputSatisfier<Pk>,
}

impl<'a, Pk: MiniscriptKey + ToPublicKey> RevaultSatisfier<'a, Pk> {
    /// Create a satisfier for a RevaultTransaction from the actual transaction, the input's index,
    /// and the descriptor of the output spent by this input.
    ///
    /// # Errors
    /// - If the input index is out of bounds.
    pub fn new(
        transaction: &'a mut impl RevaultTransaction,
        input_index: usize,
        descriptor: &'a Descriptor<Pk>,
    ) -> Result<RevaultSatisfier<'a, Pk>, Error> {
        let tx = transaction.inner_tx_mut();
        let txin = tx.input.get_mut(input_index);
        if let Some(txin) = txin {
            return Ok(RevaultSatisfier::<Pk> {
                satisfier: RevaultInputSatisfier::new(txin.sequence),
                txin,
                descriptor,
            });
        }

        Err(Error::InputSatisfaction(format!(
            "Input index '{}' out of bounds.",
            input_index,
        )))
    }

    /// Insert a signature for a given pubkey to eventually satisfy the spending conditions of the
    /// referenced utxo.
    /// This is a wrapper around the mapping from a public key to signature used by the Miniscript
    /// satisfier, and as we only ever use ALL or ALL|ANYONECANPAY signatures, this restrics the
    /// signature type using a boolean.
    pub fn insert_sig(
        &mut self,
        pubkey: Pk,
        sig: Signature,
        is_anyonecanpay: bool,
    ) -> Option<BitcoinSig> {
        self.satisfier.insert_sig(pubkey, sig, is_anyonecanpay)
    }

    /// Fulfill the txin's witness. Errors if we can't provide a valid one out of the previously
    /// given signatures.
    ///
    /// # Errors
    /// - If we could not satisfy the input.
    pub fn satisfy(&mut self) -> Result<(), Error> {
        if let Err(e) = self.descriptor.satisfy(&mut self.txin, &self.satisfier) {
            return Err(Error::InputSatisfaction(format!(
                "Script satisfaction error: {}.",
                e
            )));
        }

        Ok(())
    }
}

/// Verify this transaction validity against libbitcoinconsensus.
/// Handles all the destructuring and txout research internally.
///
/// # Errors
/// - If verification fails.
pub fn verify_revault_transaction(
    revault_tx: &impl RevaultTransaction,
    previous_transactions: &[&impl RevaultTransaction],
) -> Result<(), Error> {
    // Look for a referenced txout in the set of spent transactions
    // TODO: optimize this by walking the previous tx set only once ?
    fn get_prev_script_and_value<'a>(
        prevout: &OutPoint,
        transactions: &'a [&impl RevaultTransaction],
    ) -> Option<(&'a [u8], u64)> {
        for prev_tx in transactions {
            let tx = prev_tx.inner_tx();
            if tx.txid() == prevout.txid {
                return tx
                    .output
                    .get(prevout.vout as usize)
                    .and_then(|txo| Some((txo.script_pubkey.as_bytes(), txo.value)));
            }
        }

        None
    }

    for (index, txin) in revault_tx.inner_tx().input.iter().enumerate() {
        match get_prev_script_and_value(&txin.previous_output, &previous_transactions) {
            Some((ref raw_script_pubkey, ref value)) => {
                if let Err(err) = bitcoinconsensus::verify(
                    *raw_script_pubkey,
                    *value,
                    revault_tx.serialize().as_slice(),
                    index,
                ) {
                    return Err(Error::TransactionVerification(format!(
                        "Bitcoinconsensus error: {:?}",
                        err
                    )));
                }
            }
            None => {
                return Err(Error::TransactionVerification(format!(
                    "Unknown txout refered by txin '{:?}'",
                    txin
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CancelTransaction, EmergencyTransaction, Error, FeeBumpTransaction, RevaultSatisfier,
        RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
        VaultTransaction, RBF_SEQUENCE,
    };
    use crate::{prevouts::*, scripts::*, txouts::*};

    use rand::RngCore;
    use std::str::FromStr;

    use bitcoin::{OutPoint, PublicKey, SigHash, Transaction, TxIn, TxOut};
    use miniscript::Descriptor;

    fn get_random_privkey() -> secp256k1::SecretKey {
        let mut rand_bytes = [0u8; 32];
        let mut secret_key = Err(secp256k1::Error::InvalidSecretKey);

        while secret_key.is_err() {
            rand::thread_rng().fill_bytes(&mut rand_bytes);
            secret_key = secp256k1::SecretKey::from_slice(&rand_bytes);
        }

        secret_key.unwrap()
    }

    fn get_participants_sets(
        secp: &secp256k1::Secp256k1<secp256k1::All>,
    ) -> (
        (Vec<secp256k1::SecretKey>, Vec<PublicKey>),
        (Vec<secp256k1::SecretKey>, Vec<PublicKey>),
        (Vec<secp256k1::SecretKey>, Vec<PublicKey>),
    ) {
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

        (
            (managers_priv, managers),
            (non_managers_priv, non_managers),
            (cosigners_priv, cosigners),
        )
    }

    // Routine for ""signing"" a transaction
    fn satisfy_transaction_input(
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        tx: &mut impl RevaultTransaction,
        input_index: usize,
        tx_sighash: &SigHash,
        descriptor: &Descriptor<PublicKey>,
        secret_keys: &Vec<secp256k1::SecretKey>,
        is_anyonecanpay: bool,
    ) -> Result<(), Error> {
        let mut revault_sat =
            RevaultSatisfier::new(tx, input_index, &descriptor).expect("Creating satisfier.");
        secret_keys.iter().for_each(|privkey| {
            revault_sat.insert_sig(
                PublicKey {
                    compressed: true,
                    key: secp256k1::PublicKey::from_secret_key(&secp, &privkey),
                },
                secp.sign(
                    &secp256k1::Message::from_slice(&tx_sighash).unwrap(),
                    &privkey,
                ),
                is_anyonecanpay,
            );
        });
        revault_sat.satisfy()
    }

    // FIXME: make it return an error and expose it to the world
    macro_rules! assert_libbitcoinconsensus_validity {
        ( $tx:ident, [$($previous_tx:ident),*] ) => {
            for (index, txin) in $tx.inner_tx().input.iter().enumerate() {
                let prevout = &txin.previous_output;
                $(
                    let previous_tx = &$previous_tx.inner_tx();
                    if previous_tx.txid() == prevout.txid {
                        let (prev_script, prev_value) =
                            previous_tx
                                .output
                                .get(prevout.vout as usize)
                                .and_then(|txo| Some((txo.script_pubkey.as_bytes(), txo.value)))
                                .expect("Refered output is inexistant");
                        bitcoinconsensus::verify(
                            prev_script,
                            prev_value,
                            $tx.serialize().as_slice(),
                            index,
                        ).expect("Libbitcoinconsensus error");
                        continue;
                    }
                )*
                panic!("Could not find output pointed by txin");
            }
        };
    }

    #[test]
    fn test_transaction_creation() {
        const CSV_VALUE: u32 = 38;

        // Transactions which happened to be in my mempool
        let deposit_outpoint = OutPoint::from_str(
            "ea4a9f84cce4e5b195b496e2823f7939b474f3fd3d2d8d59b91bb2312a8113f3:0",
        )
        .unwrap();
        let feebump_outpoint = OutPoint::from_str(
            "1d239c9299a7e350e3ae6e5fb4068f13b4e01fe188a0d0533f6555aad6b17b0a:0",
        )
        .unwrap();

        let vault_prevout = VaultPrevout::new(deposit_outpoint);
        let feebump_prevout = FeeBumpPrevout::new(feebump_outpoint);

        // All the txouts created in all transactions
        let txout = TxOut {
            value: 19_000,
            ..TxOut::default()
        };
        let vault_txout = VaultTxOut::new(txout);
        let txout = TxOut {
            value: 18_000,
            ..TxOut::default()
        };
        let unvault_txout = UnvaultTxOut::new(txout);
        let txout = TxOut {
            value: 330,
            ..TxOut::default()
        };
        let cpfp_txout = CpfpTxOut::new(txout);
        let txout = TxOut {
            value: 10_000,
            ..TxOut::default()
        };
        let spend_dest_txout = ExternalTxOut::new(txout);
        let txout = TxOut {
            value: 7_000,
            ..TxOut::default()
        };
        let spend_change_txout = VaultTxOut::new(txout);
        let txout = TxOut {
            value: 17_500,
            ..TxOut::default()
        };
        let cancel_txout = VaultTxOut::new(txout);
        let txout = TxOut {
            value: 18_500,
            ..TxOut::default()
        };
        let emer_txout = EmergencyTxOut::new(txout);
        let txout = TxOut {
            value: 17_500,
            ..TxOut::default()
        };
        let emer_unvault_txout = EmergencyTxOut::new(txout);

        // All transactions we actually are going to create and sign
        let _emergency_tx =
            EmergencyTransaction::new((vault_prevout, RBF_SEQUENCE), None, emer_txout.clone());
        let _emergency_tx = EmergencyTransaction::new(
            (vault_prevout, RBF_SEQUENCE),
            Some((feebump_prevout, RBF_SEQUENCE)),
            emer_txout.clone(),
        );
        let unvault_tx = UnvaultTransaction::new(
            (vault_prevout, RBF_SEQUENCE),
            unvault_txout.clone(),
            cpfp_txout.clone(),
        );
        let unvault_prevout = UnvaultPrevout::new(unvault_tx.into_prevout(0));
        let _cancel_tx = CancelTransaction::new((unvault_prevout, RBF_SEQUENCE), None, vault_txout);
        let cancel_tx = CancelTransaction::new(
            (unvault_prevout, RBF_SEQUENCE),
            Some((feebump_prevout, RBF_SEQUENCE)),
            cancel_txout,
        );
        let _emergency_unvault_tx = UnvaultEmergencyTransaction::new(
            (unvault_prevout, RBF_SEQUENCE),
            None,
            emer_unvault_txout.clone(),
        );
        let _emergency_unvault_tx = UnvaultEmergencyTransaction::new(
            (unvault_prevout, RBF_SEQUENCE),
            Some((feebump_prevout, RBF_SEQUENCE)),
            emer_unvault_txout,
        );
        let spend_tx = SpendTransaction::new(
            &[(UnvaultPrevout::new(unvault_tx.into_prevout(0)), CSV_VALUE)],
            vec![
                SpendTxOut::Destination(spend_dest_txout),
                SpendTxOut::Change(spend_change_txout),
            ],
        );

        // We can do an additional depth as well, eg with the revaulted txo..
        let _sec_unvault_tx = UnvaultTransaction::new(
            (VaultPrevout::new(cancel_tx.into_prevout(0)), RBF_SEQUENCE),
            unvault_txout,
            cpfp_txout,
        );
        // ..Or the spend_tx's change
        let _sec_emer_tx = EmergencyTransaction::new(
            (VaultPrevout::new(spend_tx.into_prevout(1)), RBF_SEQUENCE),
            None,
            emer_txout,
        );
    }

    #[test]
    fn test_transaction_chain_satisfaction() {
        const CSV_VALUE: u32 = 42;

        let secp = secp256k1::Secp256k1::new();

        // Keys, keys, keys everywhere !
        let (
            (managers_priv, managers),
            (non_managers_priv, non_managers),
            (cosigners_priv, cosigners),
        ) = get_participants_sets(&secp);
        let all_participants_priv = managers_priv
            .iter()
            .chain(non_managers_priv.iter())
            .cloned()
            .collect::<Vec<secp256k1::SecretKey>>();

        // Get the script descriptors for the txos we're going to create
        let unvault_descriptor =
            unvault_descriptor(&non_managers, &managers, &cosigners, CSV_VALUE)
                .expect("Unvault descriptor generation error");
        let cpfp_descriptor =
            unvault_cpfp_descriptor(&managers).expect("Unvault CPFP descriptor generation error");
        let vault_descriptor = vault_descriptor(
            &managers
                .into_iter()
                .chain(non_managers.into_iter())
                .collect::<Vec<PublicKey>>(),
        )
        .expect("Vault descriptor generation error");

        // The funding transaction does not matter (random txid from my mempool)
        let vault_scriptpubkey = vault_descriptor.script_pubkey();
        let vault_raw_tx = Transaction {
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
                value: 360,
                script_pubkey: vault_scriptpubkey.clone(),
            }],
        };
        let vault_txo = VaultTxOut::new(vault_raw_tx.output[0].clone());
        let vault_tx = VaultTransaction::new(vault_raw_tx);
        let vault_prevout = VaultPrevout::new(vault_tx.into_prevout(0));

        // The fee-bumping utxo, used in revaulting transactions inputs to bump their feerate.
        // We simulate a wallet utxo.
        let feebump_secret_key = get_random_privkey();
        let feebump_pubkey = PublicKey {
            compressed: true,
            key: secp256k1::PublicKey::from_secret_key(&secp, &feebump_secret_key),
        };
        let feebump_descriptor = Descriptor::<PublicKey>::Wpkh(feebump_pubkey);
        let raw_feebump_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::from_str(
                    "4bb4545bb4bc8853cb03e42984d677fbe880c81e7d95609360eed0d8f45b52f8:0",
                )
                .unwrap(),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: 56730,
                script_pubkey: feebump_descriptor.script_pubkey(),
            }],
        };
        let feebump_txout = FeeBumpTxOut::new(raw_feebump_tx.output[0].clone());
        let feebump_tx = FeeBumpTransaction::new(raw_feebump_tx);
        let feebump_prevout = FeeBumpPrevout::new(feebump_tx.into_prevout(0));

        // Create and sign the first (vault) emergency transaction
        let emer_txo = EmergencyTxOut::new(TxOut {
            value: 450,
            ..TxOut::default()
        });
        let mut emergency_tx = EmergencyTransaction::new(
            (vault_prevout, RBF_SEQUENCE),
            Some((feebump_prevout, RBF_SEQUENCE)),
            emer_txo.clone(),
        );
        let emergency_tx_sighash_vault =
            emergency_tx.signature_hash(0, &vault_txo, &vault_descriptor.witness_script(), true);
        satisfy_transaction_input(
            &secp,
            &mut emergency_tx,
            0,
            &emergency_tx_sighash_vault,
            &vault_descriptor,
            &all_participants_priv,
            true,
        )
        .expect("Satisfying emergency transaction");
        let emergency_tx_sighash_feebump = emergency_tx.signature_hash(
            1,
            &feebump_txout,
            &feebump_descriptor.script_code().unwrap(),
            false,
        );
        satisfy_transaction_input(
            &secp,
            &mut emergency_tx,
            1,
            &emergency_tx_sighash_feebump,
            &feebump_descriptor,
            &vec![feebump_secret_key],
            false,
        )
        .expect("Satisfying feebump input of the first emergency transaction.");
        assert_libbitcoinconsensus_validity!(emergency_tx, [vault_tx, feebump_tx]);

        // Create but don't sign the unvaulting transaction until all revaulting transactions
        // are
        let (unvault_scriptpubkey, cpfp_scriptpubkey) = (
            unvault_descriptor.script_pubkey(),
            cpfp_descriptor.script_pubkey(),
        );
        let unvault_txo = UnvaultTxOut::new(TxOut {
            value: 7000,
            script_pubkey: unvault_scriptpubkey.clone(),
        });
        let cpfp_txo = CpfpTxOut::new(TxOut {
            value: 330,
            script_pubkey: cpfp_scriptpubkey,
        });
        let mut unvault_tx = UnvaultTransaction::new(
            (vault_prevout, RBF_SEQUENCE),
            unvault_txo.clone(),
            cpfp_txo.clone(),
        );
        let unvault_prevout = UnvaultPrevout::new(unvault_tx.into_prevout(0));

        // Create and sign the cancel transaction
        let revault_txo = VaultTxOut::new(TxOut {
            value: 6700,
            script_pubkey: vault_descriptor.script_pubkey(),
        });
        let mut cancel_tx = CancelTransaction::new(
            (unvault_prevout, RBF_SEQUENCE),
            Some((feebump_prevout, RBF_SEQUENCE)),
            revault_txo,
        );
        let cancel_tx_sighash =
            cancel_tx.signature_hash(0, &unvault_txo, &unvault_descriptor.witness_script(), true);
        satisfy_transaction_input(
            &secp,
            &mut cancel_tx,
            0,
            &cancel_tx_sighash,
            &unvault_descriptor,
            &all_participants_priv,
            true,
        )
        .expect("Satisfying cancel transaction");
        let cancel_tx_sighash_feebump = cancel_tx.signature_hash(
            1,
            &feebump_txout,
            &feebump_descriptor.script_code().unwrap(),
            false,
        );
        satisfy_transaction_input(
            &secp,
            &mut cancel_tx,
            1,
            &cancel_tx_sighash_feebump,
            &feebump_descriptor,
            &vec![feebump_secret_key],
            false,
        )
        .expect("Satisfying feebump input of the cancel transaction.");
        assert_libbitcoinconsensus_validity!(cancel_tx, [unvault_tx, feebump_tx]);

        // Create and sign the second (unvault) emergency transaction
        let mut unemergency_tx = UnvaultEmergencyTransaction::new(
            (unvault_prevout, RBF_SEQUENCE),
            Some((feebump_prevout, RBF_SEQUENCE)),
            emer_txo,
        );
        let unemergency_tx_sighash = unemergency_tx.signature_hash(
            0,
            &unvault_txo,
            &unvault_descriptor.witness_script(),
            true,
        );
        satisfy_transaction_input(
            &secp,
            &mut unemergency_tx,
            0,
            &unemergency_tx_sighash,
            &unvault_descriptor,
            &all_participants_priv,
            true,
        )
        .expect("Satisfying unvault emergency transaction");
        // If we don't satisfy the feebump input, libbitcoinconsensus will yell
        // uncommenting this should result in a failure:
        //assert_libbitcoinconsensus_validity!(unemergency_tx, [unvault_tx, feebump_tx]);

        // Now actually satisfy it, libbitcoinconsensus should not yell
        let unemer_tx_sighash_feebump = unemergency_tx.signature_hash(
            1,
            &feebump_txout,
            &feebump_descriptor.script_code().unwrap(),
            false,
        );
        satisfy_transaction_input(
            &secp,
            &mut unemergency_tx,
            1,
            &unemer_tx_sighash_feebump,
            &feebump_descriptor,
            &vec![feebump_secret_key],
            false,
        )
        .expect("Satisfying feebump input of the cancel transaction.");
        assert_libbitcoinconsensus_validity!(unemergency_tx, [unvault_tx, feebump_tx]);

        // Now we can sign the unvault
        let unvault_tx_sighash =
            unvault_tx.signature_hash(0, &vault_txo, &vault_descriptor.witness_script());
        satisfy_transaction_input(
            &secp,
            &mut unvault_tx,
            0,
            &unvault_tx_sighash,
            &vault_descriptor,
            &all_participants_priv,
            false,
        )
        .expect("Satisfying unvault transaction");
        assert_libbitcoinconsensus_validity!(unvault_tx, [vault_tx]);

        // Create and sign a spend transaction
        let spend_txo = ExternalTxOut::new(TxOut {
            value: 1,
            ..TxOut::default()
        });
        // Test satisfaction failure with a wrong CSV value
        let mut spend_tx = SpendTransaction::new(
            &[(unvault_prevout, CSV_VALUE - 1)],
            vec![SpendTxOut::Destination(spend_txo.clone())],
        );
        let spend_tx_sighash =
            spend_tx.signature_hash(0, &unvault_txo, &unvault_descriptor.witness_script());
        let satisfaction_res = satisfy_transaction_input(
            &secp,
            &mut spend_tx,
            0,
            &spend_tx_sighash,
            &unvault_descriptor,
            &managers_priv
                .iter()
                .chain(cosigners_priv.iter())
                .copied()
                .collect::<Vec<secp256k1::SecretKey>>(),
            false,
        );
        assert_eq!(
            satisfaction_res,
            Err(Error::InputSatisfaction(
                "Script satisfaction error: could not satisfy.".to_string()
            ))
        );

        // "This time for sure !"
        let mut spend_tx = SpendTransaction::new(
            &[(unvault_prevout, CSV_VALUE)],
            vec![SpendTxOut::Destination(spend_txo.clone())],
        );
        let spend_tx_sighash =
            spend_tx.signature_hash(0, &unvault_txo, &unvault_descriptor.witness_script());
        satisfy_transaction_input(
            &secp,
            &mut spend_tx,
            0,
            &spend_tx_sighash,
            &unvault_descriptor,
            &managers_priv
                .iter()
                .chain(cosigners_priv.iter())
                .copied()
                .collect::<Vec<secp256k1::SecretKey>>(),
            false,
        )
        .expect("Satisfying second spend transaction");
        assert_libbitcoinconsensus_validity!(spend_tx, [unvault_tx]);

        // Test that we can get the hexadecimal representation of each transaction without error
        vault_tx.hex().expect("Hex repr vault_tx");
        unvault_tx.hex().expect("Hex repr unvault_tx");
        spend_tx.hex().expect("Hex repr spend_tx");
        cancel_tx.hex().expect("Hex repr cancel_tx");
        emergency_tx.hex().expect("Hex repr emergency_tx");
        feebump_tx.hex().expect("Hex repr feebump_tx");
    }
}
