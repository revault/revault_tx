//! Revault transactions
//!
//! Typesafe routines to create bare revault transactions.

use crate::{error::Error, txins::*, txouts::*};

use bitcoin::{
    consensus::encode::{Encodable, Error as EncodeError},
    secp256k1::Signature,
    util::bip143::SigHashCache,
    OutPoint, PublicKey, Script, SigHash, SigHashType, Transaction, TxIn, TxOut,
};
use miniscript::{BitcoinSig, Descriptor, MiniscriptKey, Satisfier, ToPublicKey};

use std::collections::HashMap;
use std::fmt;

/// TxIn's sequence to set for the tx to be bip125-replaceable
pub const RBF_SEQUENCE: u32 = u32::MAX - 2;

/// A Revault transaction. Apart from the VaultTransaction, all variants must be instanciated
/// using the new_*() methods.
pub trait RevaultTransaction: fmt::Debug + Clone + PartialEq {
    /// Get the inner transaction
    fn inner_tx(&self) -> &Transaction;

    /// Get the inner transaction
    fn inner_tx_mut(&mut self) -> &mut Transaction;

    /// Get the specified output of this transaction as an OutPoint to be referenced
    /// in a following transaction.
    fn into_outpoint(&self, vout: u32) -> OutPoint {
        OutPoint {
            txid: self.inner_tx().txid(),
            vout,
        }
    }

    /// Get the network-serialized (inner) transaction
    fn serialize(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buff = Vec::<u8>::new();
        self.inner_tx().consensus_encode(&mut buff)?;
        Ok(buff)
    }

    /// Get the hexadecimal representation of the transaction as used by the bitcoind API.
    ///
    /// # Errors
    /// - If we could not encode the transaction (should not happen).
    fn hex(&self) -> Result<String, EncodeError> {
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
        #[derive(Debug, Clone, PartialEq)]
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
    ( [$($revault_txin:expr),* $(,)?], [$($txout:expr),* $(,)?], $lock_time:expr $(,)?) => {
        Transaction {
            version: 2,
            lock_time: $lock_time,
            input: vec![$(
                $revault_txin.as_unsigned_txin(),
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
        vault_input: VaultTxIn,
        unvault_txout: UnvaultTxOut,
        cpfp_txout: CpfpTxOut,
        lock_time: u32,
    ) -> UnvaultTransaction {
        UnvaultTransaction(create_tx!(
            [vault_input],
            [unvault_txout, cpfp_txout],
            lock_time,
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
        unvault_input: UnvaultTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        vault_txout: VaultTxOut,
        lock_time: u32,
    ) -> CancelTransaction {
        CancelTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!([unvault_input, feebump_input], [vault_txout], lock_time,)
        } else {
            create_tx!([unvault_input], [vault_txout], lock_time,)
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
        vault_input: VaultTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        emer_txout: EmergencyTxOut,
        lock_time: u32,
    ) -> EmergencyTransaction {
        EmergencyTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!([vault_input, feebump_input], [emer_txout], lock_time,)
        } else {
            create_tx!([vault_input], [emer_txout], lock_time,)
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
        unvault_input: UnvaultTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        emer_txout: EmergencyTxOut,
        lock_time: u32,
    ) -> UnvaultEmergencyTransaction {
        UnvaultEmergencyTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!([unvault_input, feebump_input], [emer_txout], lock_time,)
        } else {
            create_tx!([unvault_input], [emer_txout], lock_time,)
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
        unvault_inputs: &[UnvaultTxIn],
        spend_txouts: Vec<SpendTxOut>,
        lock_time: u32,
    ) -> SpendTransaction {
        SpendTransaction(Transaction {
            version: 2,
            lock_time,
            input: unvault_inputs
                .iter()
                .map(|input| input.as_unsigned_txin())
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
    doc = "The funding transaction, we don't create nor sign it."
);
impl VaultTransaction {
    /// We don't create nor are able to sign, it's just a type wrapper so explicitly no
    /// restriction on the types here
    pub fn new(tx: Transaction) -> VaultTransaction {
        VaultTransaction(tx)
    }
}

impl_revault_transaction!(
    FeeBumpTransaction,
    doc = "The fee-bumping transaction, we don't create nor sign it."
);
impl FeeBumpTransaction {
    /// We don't create nor are able to sign, it's just a type wrapper so explicitly no
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
    let mut cache = SigHashCache::new(tx);
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

#[cfg(test)]
mod tests {
    use super::{
        CancelTransaction, EmergencyTransaction, Error, FeeBumpTransaction, RevaultSatisfier,
        RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
        VaultTransaction, RBF_SEQUENCE,
    };
    use crate::{scripts::*, txins::*, txouts::*};

    use std::str::FromStr;

    use bitcoin::{
        secp256k1::rand::{rngs::SmallRng, FromEntropy, RngCore},
        util::bip32,
        OutPoint, SigHash, Transaction, TxIn, TxOut,
    };
    use miniscript::{
        descriptor::{DescriptorPublicKey, DescriptorXPub},
        Descriptor,
    };

    fn get_random_privkey(rng: &mut SmallRng) -> bip32::ExtendedPrivKey {
        let mut rand_bytes = [0u8; 64];

        rng.fill_bytes(&mut rand_bytes);

        bip32::ExtendedPrivKey::new_master(
            bitcoin::network::constants::Network::Bitcoin,
            &rand_bytes,
        )
        .unwrap_or_else(|_| get_random_privkey(rng))
    }

    /// This generates the master private keys to derive directly from master, so it's
    /// [None]<xpub_goes_here>m/* descriptor pubkeys
    fn get_participants_sets(
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    ) -> (
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
    ) {
        let mut rng = SmallRng::from_entropy();

        let managers_priv = (0..3)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let managers = managers_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXPub {
                    origin: None,
                    xpub: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    is_wildcard: true,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        let non_managers_priv = (0..8)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let non_managers = non_managers_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXPub {
                    origin: None,
                    xpub: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    is_wildcard: true,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        let cosigners_priv = (0..8)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let cosigners = cosigners_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXPub {
                    origin: None,
                    xpub: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    is_wildcard: true,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        (
            (managers_priv, managers),
            (non_managers_priv, non_managers),
            (cosigners_priv, cosigners),
        )
    }

    // Routine for ""signing"" a transaction
    fn satisfy_transaction_input(
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
        tx: &mut impl RevaultTransaction,
        input_index: usize,
        tx_sighash: &SigHash,
        descriptor: &Descriptor<DescriptorPublicKey>,
        xprivs: &Vec<bip32::ExtendedPrivKey>,
        child_number: Option<bip32::ChildNumber>,
        is_anyonecanpay: bool,
    ) -> Result<(), Error> {
        let mut revault_sat =
            RevaultSatisfier::new(tx, input_index, &descriptor).expect("Creating satisfier.");
        // Can we agree that rustfmt does some nasty formatting now ??
        let derivation_path = bip32::DerivationPath::from(if let Some(cn) = child_number {
            vec![cn]
        } else {
            vec![]
        });
        xprivs.iter().for_each(|xpriv| {
            // As key, we store the master xpub with the path to the actual pubkey for this sig
            // so that to_public_key() returns this one.
            revault_sat.insert_sig(
                DescriptorPublicKey::XPub(DescriptorXPub {
                    origin: None,
                    xpub: bip32::ExtendedPubKey::from_private(&secp, xpriv),
                    derivation_path: derivation_path.clone(),
                    is_wildcard: false,
                }),
                secp.sign(
                    &bitcoin::secp256k1::Message::from_slice(&tx_sighash).unwrap(),
                    &xpriv
                        .derive_priv(&secp, &derivation_path)
                        .unwrap()
                        .private_key
                        .key,
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
                            $tx.serialize().expect("Serializing tx").as_slice(),
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
    fn test_transaction_chain_satisfaction() {
        const CSV_VALUE: u32 = 42;

        let secp = bitcoin::secp256k1::Secp256k1::new();

        // Let's get the 10th key of each
        let child_number = bip32::ChildNumber::from(10);

        // Keys, keys, keys everywhere !
        let (
            (managers_priv, managers),
            (non_managers_priv, non_managers),
            (cosigners_priv, cosigners),
        ) = get_participants_sets(&secp);
        let all_participants_xpriv = managers_priv
            .iter()
            .chain(non_managers_priv.iter())
            .cloned()
            .collect::<Vec<bip32::ExtendedPrivKey>>();

        // Get the script descriptors for the txos we're going to create
        let unvault_descriptor = unvault_descriptor(
            non_managers.clone(),
            managers.clone(),
            cosigners.clone(),
            CSV_VALUE,
        )
        .expect("Unvault descriptor generation error")
        .derive(child_number);
        let cpfp_descriptor = unvault_cpfp_descriptor(managers.clone())
            .expect("Unvault CPFP descriptor generation error")
            .derive(child_number);
        let vault_descriptor = vault_descriptor(
            managers
                .into_iter()
                .chain(non_managers.into_iter())
                .collect::<Vec<DescriptorPublicKey>>(),
        )
        .expect("Vault descriptor generation error")
        .derive(child_number);

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
        let vault_txo = VaultTxOut::new(vault_raw_tx.output[0].value, &vault_descriptor);
        let vault_tx = VaultTransaction::new(vault_raw_tx);

        // The fee-bumping utxo, used in revaulting transactions inputs to bump their feerate.
        // We simulate a wallet utxo.
        let mut rng = SmallRng::from_entropy();
        let feebump_xpriv = get_random_privkey(&mut rng);
        let feebump_xpub = bip32::ExtendedPubKey::from_private(&secp, &feebump_xpriv);
        let feebump_descriptor =
            Descriptor::<DescriptorPublicKey>::Wpkh(DescriptorPublicKey::XPub(DescriptorXPub {
                origin: None,
                xpub: feebump_xpub,
                derivation_path: bip32::DerivationPath::from(vec![]),
                is_wildcard: false, // We are not going to derive from this one
            }));
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
        let feebump_txo = FeeBumpTxOut::new(raw_feebump_tx.output[0].clone());
        let feebump_tx = FeeBumpTransaction::new(raw_feebump_tx);

        // Create and sign the first (vault) emergency transaction
        let vault_txin = VaultTxIn::new(vault_tx.into_outpoint(0), vault_txo.clone(), RBF_SEQUENCE);
        let feebump_txin = FeeBumpTxIn::new(
            feebump_tx.into_outpoint(0),
            feebump_txo.clone(),
            RBF_SEQUENCE,
        );
        let emer_txo = EmergencyTxOut::new(TxOut {
            value: 450,
            ..TxOut::default()
        });
        let mut emergency_tx =
            EmergencyTransaction::new(vault_txin, Some(feebump_txin), emer_txo.clone(), 0);
        let emergency_tx_sighash_vault =
            emergency_tx.signature_hash(0, &vault_txo, &vault_descriptor.witness_script(), true);
        satisfy_transaction_input(
            &secp,
            &mut emergency_tx,
            0,
            &emergency_tx_sighash_vault,
            &vault_descriptor,
            &all_participants_xpriv,
            Some(child_number),
            true,
        )
        .expect("Satisfying emergency transaction");

        let emergency_tx_sighash_feebump =
            emergency_tx.signature_hash(1, &feebump_txo, &feebump_descriptor.script_code(), false);
        satisfy_transaction_input(
            &secp,
            &mut emergency_tx,
            1,
            &emergency_tx_sighash_feebump,
            &feebump_descriptor,
            &vec![feebump_xpriv],
            None,
            false,
        )
        .expect("Satisfying feebump input of the first emergency transaction.");
        assert_libbitcoinconsensus_validity!(emergency_tx, [vault_tx, feebump_tx]);

        // Create but don't sign the unvaulting transaction until all revaulting transactions
        // are
        let vault_txin = VaultTxIn::new(vault_tx.into_outpoint(0), vault_txo.clone(), u32::MAX);
        let unvault_txo = UnvaultTxOut::new(7000, &unvault_descriptor);
        let cpfp_txo = CpfpTxOut::new(330, &cpfp_descriptor);
        let mut unvault_tx =
            UnvaultTransaction::new(vault_txin, unvault_txo.clone(), cpfp_txo.clone(), 0);

        // Create and sign the cancel transaction
        let unvault_txin = UnvaultTxIn::new(
            unvault_tx.into_outpoint(0),
            unvault_txo.clone(),
            RBF_SEQUENCE,
        );
        let feebump_txin = FeeBumpTxIn::new(
            feebump_tx.into_outpoint(0),
            feebump_txo.clone(),
            RBF_SEQUENCE,
        );
        let revault_txo = VaultTxOut::new(6700, &vault_descriptor);
        let mut cancel_tx =
            CancelTransaction::new(unvault_txin, Some(feebump_txin), revault_txo, 0);
        let cancel_tx_sighash =
            cancel_tx.signature_hash(0, &unvault_txo, &unvault_descriptor.witness_script(), true);
        satisfy_transaction_input(
            &secp,
            &mut cancel_tx,
            0,
            &cancel_tx_sighash,
            &unvault_descriptor,
            &all_participants_xpriv,
            Some(child_number),
            true,
        )
        .expect("Satisfying cancel transaction");
        let cancel_tx_sighash_feebump =
            cancel_tx.signature_hash(1, &feebump_txo, &feebump_descriptor.script_code(), false);

        satisfy_transaction_input(
            &secp,
            &mut cancel_tx,
            1,
            &cancel_tx_sighash_feebump,
            &feebump_descriptor,
            &vec![feebump_xpriv],
            None, // No derivation path for the feebump key
            false,
        )
        .expect("Satisfying feebump input of the cancel transaction.");
        assert_libbitcoinconsensus_validity!(cancel_tx, [unvault_tx, feebump_tx]);

        // Create and sign the second (unvault) emergency transaction
        let unvault_txin = UnvaultTxIn::new(
            unvault_tx.into_outpoint(0),
            unvault_txo.clone(),
            RBF_SEQUENCE,
        );
        let feebump_txin = FeeBumpTxIn::new(
            feebump_tx.into_outpoint(0),
            feebump_txo.clone(),
            RBF_SEQUENCE,
        );
        let mut unemergency_tx =
            UnvaultEmergencyTransaction::new(unvault_txin, Some(feebump_txin), emer_txo, 0);
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
            &all_participants_xpriv,
            Some(child_number),
            true,
        )
        .expect("Satisfying unvault emergency transaction");
        // If we don't satisfy the feebump input, libbitcoinconsensus will yell
        // uncommenting this should result in a failure:
        //assert_libbitcoinconsensus_validity!(unemergency_tx, [unvault_tx, feebump_tx]);

        // Now actually satisfy it, libbitcoinconsensus should not yell
        let unemer_tx_sighash_feebump = unemergency_tx.signature_hash(
            1,
            &feebump_txo,
            &feebump_descriptor.script_code(),
            false,
        );
        satisfy_transaction_input(
            &secp,
            &mut unemergency_tx,
            1,
            &unemer_tx_sighash_feebump,
            &feebump_descriptor,
            &vec![feebump_xpriv],
            None,
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
            &all_participants_xpriv,
            Some(child_number),
            false,
        )
        .expect("Satisfying unvault transaction");
        assert_libbitcoinconsensus_validity!(unvault_tx, [vault_tx]);

        // FIXME: We should test batching as well for the spend transaction
        // Create and sign a spend transaction
        let unvault_txin = UnvaultTxIn::new(
            unvault_tx.into_outpoint(0),
            unvault_txo.clone(),
            CSV_VALUE - 1,
        );
        let spend_txo = ExternalTxOut::new(TxOut {
            value: 1,
            ..TxOut::default()
        });
        // Test satisfaction failure with a wrong CSV value
        let mut spend_tx = SpendTransaction::new(
            &[unvault_txin],
            vec![SpendTxOut::Destination(spend_txo.clone())],
            0,
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
                .collect::<Vec<bip32::ExtendedPrivKey>>(),
            Some(child_number),
            false,
        );
        assert_eq!(
            satisfaction_res,
            Err(Error::InputSatisfaction(
                "Script satisfaction error: could not satisfy.".to_string()
            ))
        );

        // "This time for sure !"
        let unvault_txin = UnvaultTxIn::new(
            unvault_tx.into_outpoint(0),
            unvault_txo.clone(),
            CSV_VALUE, // The valid sequence this time
        );
        let mut spend_tx = SpendTransaction::new(
            &[unvault_txin],
            vec![SpendTxOut::Destination(spend_txo.clone())],
            0,
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
                .collect::<Vec<bip32::ExtendedPrivKey>>(),
            Some(child_number),
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
