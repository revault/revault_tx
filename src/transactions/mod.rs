//! Revault transactions
//!
//! Typesafe routines to create Revault-specific Bitcoin transactions.
//!
//! We use PSBTs as defined in [bip-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
//! for data structure as well as roles distribution.

use crate::{error::*, scripts::*, txins::*, txouts::*};
use miniscript::{
    bitcoin::{
        consensus::encode::Encodable,
        secp256k1,
        util::{
            bip143::SigHashCache, bip32::ChildNumber, psbt::PartiallySignedTransaction as Psbt,
        },
        Address, Amount, Network, OutPoint, PublicKey as BitcoinPubKey, SigHash, SigHashType,
        Transaction, Txid, Wtxid,
    },
    DescriptorTrait,
};

use std::{
    collections::{BTreeMap, HashMap},
    convert::TryInto,
    fmt,
};

#[macro_use]
mod utils;

mod cancel;
mod cpfp;
mod emergency;
mod spend;
mod unvault;
mod unvaultemergency;

pub use cancel::CancelTransaction;
pub use cpfp::CpfpTransaction;
pub use emergency::EmergencyTransaction;
pub use spend::SpendTransaction;
pub use unvault::UnvaultTransaction;
pub use unvaultemergency::UnvaultEmergencyTransaction;

/// The value of the CPFP output in the Unvault transaction.
/// See [practical-revault](https://github.com/revault/practical-revault/blob/master/transactions.md#unvault_tx).
pub const UNVAULT_CPFP_VALUE: u64 = 30000;

/// The feerate, in sat / WU, to create the unvaulting transactions with.
pub const UNVAULT_TX_FEERATE: u64 = 6;

/// The feerate, in sat / WU, to create the Emergency transactions with.
pub const EMER_TX_FEERATE: u64 = 250;

/// The minimum value of a deposit UTxO for creating a transaction chain from it.
pub const DEPOSIT_MIN_SATS: u64 = 500_000;

/// The minimum value of a deposit UTxO created by a Cancel transaction.
pub const CANCEL_DEPOSIT_MIN_SATS: u64 = 5_000;

/// We can't safely error for insane fees on revaulting transactions, but we can for the unvault
/// and the spend. This is 0.2BTC, or 3k€ currently.
pub const INSANE_FEES: u64 = 20_000_000;

/// This enables CSV and is easier to apply to all transactions anyways.
pub const TX_VERSION: i32 = 2;

/// The default nLockTime used. Note we can't set it to prevent fee sniping for pre-signed
/// transactions.
pub const TX_LOCKTIME: u32 = 0;

/// Maximum weight of a transaction to be relayed.
///
/// <https://github.com/bitcoin/bitcoin/blob/590e49ccf2af27c6c1f1e0eb8be3a4bf4d92ce8b/src/policy/policy.h#L23-L24>
pub const MAX_STANDARD_TX_WEIGHT: u32 = 400_000;

/// The min value for which we'll create a change in a CpfpTransaction. In other words: if the sum
/// of the inputs minus the fees is less than CPFP_MIN_CHANGE, we'll throw everything in fees.
pub const CPFP_MIN_CHANGE: u64 = 10_000;

/// This private module is used to make mutable references to the PSBT inside transaction newtypes
/// available to functions inside the transaction module, but not beyond that. This is needed to
/// guarantee invariants that could not be guaranteed if users had arbitrary mutable access to the
/// inner PSBT.
pub(super) mod inner_mut {
    use super::{Psbt, TransactionSerialisationError};

    pub trait PrivateInnerMut: Sized {
        /// Get a mutable reference to the inner transaction, this is only used internally
        fn psbt_mut(&mut self) -> &mut Psbt;

        /// Get a reference to the inner transaction, this is only used internally
        fn psbt(&self) -> &Psbt;

        /// Move inner PSBT out
        fn into_psbt(self) -> Psbt;

        /// Create a RevaultTransaction from a base64-encoded BIP174-serialized transaction.
        fn from_psbt_serialized(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError>;
    }
}

/// A Revault transaction.
///
/// Wraps a rust-bitcoin PSBT and defines some BIP174 roles as methods.
/// Namely:
/// - Creator and updater
/// - Signer
/// - Finalizer
/// - Extractor and serializer
pub trait RevaultTransaction: fmt::Debug + Clone + PartialEq {
    /// Get a reference to the inner PSBT
    fn psbt(&self) -> &Psbt;

    /// Move inner PSBT out
    fn into_psbt(self) -> Psbt;

    /// Get the sighash for an input of a Revault transaction. Will deduce the scriptCode from
    /// the previous witness script.
    /// NOTE: transactions are always signed with the SIGHASH_ALL flag.
    ///
    /// ## Errors
    /// - if the input is out of bounds
    /// - if the RevaultTransaction was already finalized
    fn signature_hash(&self, input_index: usize) -> Result<SigHash, InputSatisfactionError>;

    /// Cached version of [RevaultTransaction::signature_hash]
    fn signature_hash_cached(
        &self,
        input_index: usize,
        cache: &mut SigHashCache<&Transaction>,
    ) -> Result<SigHash, InputSatisfactionError>;

    /// Add a signature in order to eventually satisfy this input.
    ///
    /// NOTE: this checks the signature. The expected signature type is ALL.
    ///
    /// The BIP174 Signer role.
    fn add_signature<C: secp256k1::Verification>(
        &mut self,
        input_index: usize,
        pubkey: secp256k1::PublicKey,
        signature: secp256k1::Signature,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Option<Vec<u8>>, InputSatisfactionError>;

    /// Check and satisfy the scripts, create the witnesses.
    ///
    /// The BIP174 Input Finalizer role.
    fn finalize(
        &mut self,
        ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    ) -> Result<(), Error>;

    /// Check the transaction is valid (fully-signed) and can be finalized.
    /// Slighty more efficient than calling [RevaultTransaction::finalize] on a clone as it gets
    /// rid of the belt-and-suspenders checks.
    fn is_finalizable(&self, ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>) -> bool;

    /// Check if the transaction was already finalized.
    fn is_finalized(&self) -> bool;

    /// Check the transaction is valid
    fn is_valid(&self, ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>) -> bool;

    /// Verify all PSBT inputs against libbitcoinconsensus
    fn verify_inputs(&self) -> Result<(), Error>;

    /// Get the network-serialized (inner) transaction. You likely want to be sure
    /// the transaction [RevaultTransaction.is_finalized] before serializing it.
    ///
    /// The BIP174 Transaction Extractor (without any check, which are done in
    /// [RevaultTransaction.finalize]).
    fn into_bitcoin_serialized(self) -> Vec<u8>;

    /// Get the BIP174-serialized (inner) transaction.
    fn as_psbt_serialized(&self) -> Vec<u8>;

    /// Create a RevaultTransaction from a base64-encoded BIP174-serialized transaction.
    fn from_psbt_serialized(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError>;

    /// Get the BIP174-serialized (inner) transaction encoded in base64.
    fn as_psbt_string(&self) -> String;

    /// Create a RevaultTransaction from a base64-encoded BIP174-serialized transaction.
    fn from_psbt_str(psbt_str: &str) -> Result<Self, TransactionSerialisationError>;

    /// Sum of the inputs' value minus the sum of the outputs' value
    fn fees(&self) -> Amount;

    /// Get the inner unsigned transaction id
    fn txid(&self) -> Txid;

    /// Get the inner unsigned transaction hash with witness data
    fn wtxid(&self) -> Wtxid;

    /// Get a reference to the inner transaction
    fn tx(&self) -> &Transaction;

    /// Extract the inner transaction of the inner PSBT. You likely want to be sure
    /// the transaction [RevaultTransaction.is_finalized] before serializing it.
    ///
    /// The BIP174 Transaction Extractor (without any check, which are done in
    /// [RevaultTransaction.finalize]).
    fn into_tx(self) -> Transaction;
}

/// A Revault transaction which is signed in advance and whose signatures are exchanged by
/// the participants.
/// Contains a single transaction input.
pub trait RevaultPresignedTransaction: RevaultTransaction {
    /// Get the sighash for the single input of a presigned Revault transaction.
    fn sig_hash(&self) -> Result<SigHash, InputSatisfactionError> {
        debug_assert_eq!(
            self.psbt().inputs.len(),
            1,
            "Presigned transactions are always created with a single input"
        );
        RevaultTransaction::signature_hash(self, 0)
    }

    /// Cached version of [RevaultPresignedTransaction::signature_hash]
    fn sig_hash_cached(
        &self,
        cache: &mut SigHashCache<&Transaction>,
    ) -> Result<SigHash, InputSatisfactionError> {
        debug_assert_eq!(
            self.psbt().inputs.len(),
            1,
            "Presigned transactions are always created with a single input"
        );
        RevaultTransaction::signature_hash_cached(self, 0, cache)
    }

    /// Add a signature to the single input of a presigned Revault transaction.
    ///
    /// NOTE: this checks the signature. The expected signature type is ALL.
    fn add_sig<C: secp256k1::Verification>(
        &mut self,
        pubkey: secp256k1::PublicKey,
        signature: secp256k1::Signature,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Option<Vec<u8>>, InputSatisfactionError> {
        debug_assert_eq!(
            self.psbt().inputs.len(),
            1,
            "Presigned transactions are always created with a single input"
        );
        RevaultTransaction::add_signature(self, 0, pubkey, signature, secp)
    }

    /// Get the signatures for the single input of this presigned Revault transaction.
    fn signatures(&self) -> &BTreeMap<BitcoinPubKey, Vec<u8>> {
        &self.psbt().inputs[0].partial_sigs
    }
}

impl<T: inner_mut::PrivateInnerMut + fmt::Debug + Clone + PartialEq> RevaultTransaction for T {
    fn psbt(&self) -> &Psbt {
        inner_mut::PrivateInnerMut::psbt(self)
    }

    fn into_psbt(self) -> Psbt {
        inner_mut::PrivateInnerMut::into_psbt(self)
    }

    fn signature_hash(&self, input_index: usize) -> Result<SigHash, InputSatisfactionError> {
        let mut cache = SigHashCache::new(self.tx());
        self.signature_hash_cached(input_index, &mut cache)
    }

    fn signature_hash_cached(
        &self,
        input_index: usize,
        cache: &mut SigHashCache<&Transaction>,
    ) -> Result<SigHash, InputSatisfactionError> {
        let psbt = self.psbt();
        let psbtin = psbt
            .inputs
            .get(input_index)
            .ok_or(InputSatisfactionError::OutOfBounds)?;
        let prev_txo = psbtin
            .witness_utxo
            .as_ref()
            .expect("We always set witness_txo");

        assert!(prev_txo.script_pubkey.is_v0_p2wsh());
        let witscript = psbtin
            .witness_script
            .as_ref()
            .ok_or(InputSatisfactionError::MissingWitnessScript)?;
        Ok(cache.signature_hash(input_index, &witscript, prev_txo.value, SigHashType::All))
    }

    fn add_signature<C: secp256k1::Verification>(
        &mut self,
        input_index: usize,
        pubkey: secp256k1::PublicKey,
        signature: secp256k1::Signature,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Option<Vec<u8>>, InputSatisfactionError> {
        let psbtin = self
            .psbt()
            .inputs
            .get(input_index)
            .ok_or(InputSatisfactionError::OutOfBounds)?;

        // If we were already finalized, our witness script was wiped.
        if psbtin.final_script_witness.is_some() {
            return Err(InputSatisfactionError::AlreadyFinalized);
        }

        // BIP174:
        // For a Signer to only produce valid signatures for what it expects to sign, it must
        // check that the following conditions are true:
        // -- If a witness UTXO is provided, no non-witness signature may be created.
        let prev_txo = psbtin
            .witness_utxo
            .as_ref()
            .expect("Cannot be reached. We only create transactions with witness_utxo.");
        assert!(
            psbtin.non_witness_utxo.is_none(),
            "We never create transactions with non_witness_utxo."
        );

        // -- If a witnessScript is provided, the scriptPubKey or the redeemScript must be for
        // that witnessScript
        let witness_script = psbtin.witness_script.as_ref().expect("We only use wsh");
        // Note the network is irrelevant here.
        let expected_script_pubkey =
            Address::p2wsh(witness_script, Network::Bitcoin).script_pubkey();
        assert!(
            expected_script_pubkey == prev_txo.script_pubkey,
            "We create TxOut scriptPubKey out of this exact witnessScript."
        );
        assert!(
            psbtin.redeem_script.is_none(),
            "We never create Psbt input with legacy txos."
        );

        let sighash = self.signature_hash(input_index)?;
        let sighash = secp256k1::Message::from_slice(&sighash).expect("sighash is 32 a bytes hash");
        secp.verify(&sighash, &signature, &pubkey)
            .map_err(|_| InputSatisfactionError::InvalidSignature(signature, pubkey, sighash))?;

        let pubkey = BitcoinPubKey {
            compressed: true,
            key: pubkey,
        };
        let mut rawsig = signature.serialize_der().to_vec();
        rawsig.push(SigHashType::All.as_u32() as u8);

        let psbtin = self
            .psbt_mut()
            .inputs
            .get_mut(input_index)
            .expect("Checked at the beginning.");
        Ok(psbtin.partial_sigs.insert(pubkey, rawsig))
    }

    fn finalize(
        &mut self,
        ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    ) -> Result<(), Error> {
        // We could operate on a clone for state consistency in case of error. But we can only end
        // up in an inconsistent state if miniscript's interpreter checks pass but not
        // libbitcoinconsensus' one.
        let mut psbt = self.psbt_mut();

        miniscript::psbt::finalize(&mut psbt, ctx)
            .map_err(|e| Error::TransactionFinalisation(e.to_string()))?;

        // Miniscript's finalize does not check against libbitcoinconsensus. And we are better safe
        // than sorry when dealing with Script ...
        self.verify_inputs()?;

        Ok(())
    }

    /// Check the transaction is valid (fully-signed) and can be finalized.
    /// Slighty more efficient than calling [RevaultTransaction::finalize] on a clone as it gets
    /// rid of the belt-and-suspenders checks.
    fn is_finalizable(&self, ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>) -> bool {
        miniscript::psbt::finalize(&mut self.psbt().clone(), ctx).is_ok()
    }

    /// Check if the transaction was already finalized.
    fn is_finalized(&self) -> bool {
        for i in self.psbt().inputs.iter() {
            // We never mix finalized and non-finalized inputs.
            if i.final_script_witness.is_some() {
                return true;
            }
        }

        false
    }

    /// Check the transaction is valid
    fn is_valid(&self, ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>) -> bool {
        if !self.is_finalized() {
            return false;
        }

        // Miniscript's finalize does not check against libbitcoinconsensus. And we are better safe
        // than sorry when dealing with Script ...
        if self.verify_inputs().is_err() {
            return false;
        }
        assert_eq!(self.psbt().inputs.len(), self.tx().input.len());

        miniscript::psbt::interpreter_check(&self.psbt(), ctx).is_ok()
    }

    /// Verify all PSBT inputs against libbitcoinconsensus
    fn verify_inputs(&self) -> Result<(), Error> {
        let ser_tx = self.clone().into_bitcoin_serialized();

        for (i, psbtin) in self.psbt().inputs.iter().enumerate() {
            let utxo = psbtin
                .witness_utxo
                .as_ref()
                .expect("A witness_utxo is always set");
            let (prev_scriptpubkey, prev_value) = (utxo.script_pubkey.as_bytes(), utxo.value);

            bitcoinconsensus::verify(prev_scriptpubkey, prev_value, &ser_tx, i)?;
        }

        Ok(())
    }

    /// Get the network-serialized (inner) transaction. You likely want to be sure
    /// the transaction [RevaultTransaction.is_finalized] before serializing it.
    ///
    /// The BIP174 Transaction Extractor (without any check, which are done in
    /// [RevaultTransaction.finalize]).
    fn into_bitcoin_serialized(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        self.into_psbt()
            .extract_tx()
            .consensus_encode(&mut buf)
            .expect("We only create valid PSBT, serialization cannot fail");
        buf
    }

    /// Get the BIP174-serialized (inner) transaction.
    fn as_psbt_serialized(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(256);
        self.psbt()
            .consensus_encode(&mut buff)
            .expect("We only create valid PSBT, serialization cannot fail");
        buff
    }

    /// Get the BIP174-serialized (inner) transaction encoded in base64.
    fn as_psbt_string(&self) -> String {
        base64::encode(self.as_psbt_serialized())
    }

    /// Create a RevaultTransaction from a base64-encoded BIP174-serialized transaction.
    fn from_psbt_str(psbt_str: &str) -> Result<Self, TransactionSerialisationError> {
        Self::from_psbt_serialized(&base64::decode(&psbt_str)?)
    }

    /// Create a RevaultTransaction from a base64-encoded BIP174-serialized transaction.
    fn from_psbt_serialized(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        use crate::transactions::inner_mut::PrivateInnerMut;
        <T as PrivateInnerMut>::from_psbt_serialized(raw_psbt)
    }

    /// Return the absolute fees this transaction is paying.
    fn fees(&self) -> Amount {
        // We always set witness_utxo, it can only be a bug we introduced with amounts.
        utils::psbt_fees(self.psbt()).expect("Fee computation bug: overflow")
    }

    /// Get the inner unsigned transaction id
    fn txid(&self) -> Txid {
        self.psbt().global.unsigned_tx.txid()
    }

    /// Get the inner unsigned transaction hash with witness data
    fn wtxid(&self) -> Wtxid {
        self.psbt().global.unsigned_tx.wtxid()
    }

    /// Get a reference to the inner transaction
    fn tx(&self) -> &Transaction {
        &self.psbt().global.unsigned_tx
    }

    /// Extract the inner transaction of the inner PSBT. You likely want to be sure
    /// the transaction [RevaultTransaction.is_finalized] before serializing it.
    ///
    /// The BIP174 Transaction Extractor (without any check, which are done in
    /// [RevaultTransaction.finalize]).
    fn into_tx(self) -> Transaction {
        self.into_psbt().extract_tx()
    }
}

/// A transaction that can be CPFPed
pub trait CpfpableTransaction: RevaultTransaction {
    /// Return the txin refering to the output to spend to CPFP this transaction, if any.
    fn cpfp_txin(
        &self,
        cpfp_descriptor: &CpfpDescriptor,
        secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    ) -> Option<CpfpTxIn> {
        let psbtouts = &self.psbt().outputs;

        for i in 0..psbtouts.len() {
            // For instance the external outputs of the Spend have no bip32_derivation
            if psbtouts[i].bip32_derivation.is_empty() {
                continue;
            }

            // But when we do set it, the path always have a depth of 1
            let der_path = &psbtouts[i].bip32_derivation.values().next().unwrap().1;
            assert_eq!(der_path.len(), 1,);
            let der_index = der_path[0];
            let der_cpfp_desc = cpfp_descriptor.derive(der_index, secp);

            // Is it the CPFP txo?
            if self.tx().output[i].script_pubkey == der_cpfp_desc.inner().script_pubkey() {
                let txo = &self.tx().output[i];
                let prev_txout = CpfpTxOut::new(Amount::from_sat(txo.value), &der_cpfp_desc);
                return Some(CpfpTxIn::new(
                    OutPoint {
                        txid: self.txid(),
                        vout: i.try_into().expect("vout doesn't fit in a u32?"),
                    },
                    prev_txout,
                ));
            }
        }

        None
    }

    /// Get the feerate of this transaction, assuming fully-satisfied inputs. If the transaction
    /// is already finalized, returns the exact feerate. Otherwise computes the maximum reasonable
    /// weight of a satisfaction and returns the feerate based on this estimation.
    fn max_feerate(&self) -> u64 {
        let fees = self.fees().as_sat();
        let weight = self.max_weight();

        fees.checked_add(weight - 1) // Weight is never 0
            .expect("Feerate computation bug, fees >u64::MAX")
            .checked_div(weight)
            .expect("Weight is never 0")
    }

    /// Get the size of this transaction, assuming fully-satisfied inputs. If the transaction
    /// is already finalized, returns the exact size in witness units. Otherwise computes the
    /// maximum reasonable weight of a satisfaction.
    fn max_weight(&self) -> u64;
}

/// The funding transaction, we don't create nor sign it.
#[derive(Debug, Clone, PartialEq)]
pub struct DepositTransaction(pub Transaction);
impl DepositTransaction {
    /// Assumes that the outpoint actually refers to this transaction. Will panic otherwise.
    pub fn deposit_txin(
        &self,
        outpoint: OutPoint,
        deposit_descriptor: &DerivedDepositDescriptor,
    ) -> DepositTxIn {
        assert!(outpoint.txid == self.0.txid());
        let txo = self.0.output[outpoint.vout as usize].clone();

        DepositTxIn::new(
            outpoint,
            DepositTxOut::new(Amount::from_sat(txo.value), deposit_descriptor),
        )
    }
}

/// A set of Cancel transactions signed at fixed feerates.
#[derive(Debug, Clone)]
pub struct CancelTransactionsBatch {
    /// CancelTransaction created with a feerate of 20sats/vbyte
    feerate_20: CancelTransaction,
    /// CancelTransaction created with a feerate of 100sats/vbyte
    feerate_100: CancelTransaction,
    /// CancelTransaction created with a feerate of 200sats/vbyte
    feerate_200: CancelTransaction,
    /// CancelTransaction created with a feerate of 500sats/vbyte
    feerate_500: CancelTransaction,
    /// CancelTransaction created with a feerate of 1000sats/vbyte
    feerate_1000: CancelTransaction,
}

impl CancelTransactionsBatch {
    /// Create a new batch of Cancel transactions presigned with feerates of 20, 100, 200, 500 and
    /// 1000 sats/vbyte.
    pub fn new(
        unvault_txin: UnvaultTxIn,
        der_deposit_descriptor: &DerivedDepositDescriptor,
    ) -> Result<CancelTransactionsBatch, TransactionCreationError> {
        Ok(CancelTransactionsBatch {
            feerate_20: CancelTransaction::new(
                unvault_txin.clone(),
                &der_deposit_descriptor,
                Amount::from_sat(5), // vbytes to WU
            )?,
            feerate_100: CancelTransaction::new(
                unvault_txin.clone(),
                &der_deposit_descriptor,
                Amount::from_sat(25), // vbytes to WU
            )?,
            feerate_200: CancelTransaction::new(
                unvault_txin.clone(),
                &der_deposit_descriptor,
                Amount::from_sat(50), // vbytes to WU
            )?,
            feerate_500: CancelTransaction::new(
                unvault_txin.clone(),
                &der_deposit_descriptor,
                Amount::from_sat(125), // vbytes to WU
            )?,
            feerate_1000: CancelTransaction::new(
                unvault_txin,
                &der_deposit_descriptor,
                Amount::from_sat(250), // vbytes to WU
            )?,
        })
    }

    /// Get a reference to the Cancel transaction created with a feerate of 20sats/vbyte
    pub fn feerate_20(&self) -> &CancelTransaction {
        &self.feerate_20
    }

    /// Move out the Cancel transaction created with a feerate of 20sats/vbyte
    pub fn into_feerate_20(self) -> CancelTransaction {
        self.feerate_20
    }

    /// Get a reference to the Cancel transaction created with a feerate of 100sats/vbyte
    pub fn feerate_100(&self) -> &CancelTransaction {
        &self.feerate_100
    }

    /// Move out the Cancel transaction created with a feerate of 100sats/vbyte
    pub fn into_feerate_100(self) -> CancelTransaction {
        self.feerate_100
    }

    /// Get a reference to the Cancel transaction created with a feerate of 200sats/vbyte
    pub fn feerate_200(&self) -> &CancelTransaction {
        &self.feerate_200
    }

    /// Move out the Cancel transaction created with a feerate of 200sats/vbyte
    pub fn into_feerate_200(self) -> CancelTransaction {
        self.feerate_200
    }

    /// Get a reference to the Cancel transaction created with a feerate of 500sats/vbyte
    pub fn feerate_500(&self) -> &CancelTransaction {
        &self.feerate_500
    }

    /// Move out the Cancel transaction created with a feerate of 500sats/vbyte
    pub fn into_feerate_500(self) -> CancelTransaction {
        self.feerate_500
    }

    /// Get a reference to the Cancel transaction created with a feerate of 1000sats/vbyte
    pub fn feerate_1000(&self) -> &CancelTransaction {
        &self.feerate_1000
    }

    /// Move out the Cancel transaction created with a feerate of 1000sats/vbyte
    pub fn into_feerate_1000(self) -> CancelTransaction {
        self.feerate_1000
    }

    /// Get all the Cancel transactions, ordered by ascending feerate
    pub fn all_feerates(self) -> [CancelTransaction; 5] {
        [
            self.feerate_20,
            self.feerate_100,
            self.feerate_200,
            self.feerate_500,
            self.feerate_1000,
        ]
    }

    /// Get a map of feerate to Cancel tx for all available feerates
    pub fn feerates_map(self) -> HashMap<Amount, CancelTransaction> {
        // We can't use IntoIterator::into_iter to iter over an array by value on 1.43.
        let mut map = HashMap::with_capacity(5);

        map.insert(Amount::from_sat(20), self.feerate_20);
        map.insert(Amount::from_sat(100), self.feerate_100);
        map.insert(Amount::from_sat(200), self.feerate_200);
        map.insert(Amount::from_sat(500), self.feerate_500);
        map.insert(Amount::from_sat(1_000), self.feerate_1000);

        map
    }
}

/// Get the chain of pre-signed transactions out of a deposit available for a manager.
#[allow(clippy::too_many_arguments)]
pub fn transaction_chain_manager<C: secp256k1::Verification>(
    deposit_outpoint: OutPoint,
    deposit_amount: Amount,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    derivation_index: ChildNumber,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<(UnvaultTransaction, CancelTransactionsBatch), Error> {
    let (der_deposit_descriptor, der_unvault_descriptor, der_cpfp_descriptor) = (
        deposit_descriptor.derive(derivation_index, secp),
        unvault_descriptor.derive(derivation_index, secp),
        cpfp_descriptor.derive(derivation_index, secp),
    );

    let deposit_txin = DepositTxIn::new(
        deposit_outpoint,
        DepositTxOut::new(deposit_amount, &der_deposit_descriptor),
    );
    let unvault_tx =
        UnvaultTransaction::new(deposit_txin, &der_unvault_descriptor, &der_cpfp_descriptor)?;

    let unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
    let cancel_batch = CancelTransactionsBatch::new(unvault_txin, &der_deposit_descriptor)?;

    Ok((unvault_tx, cancel_batch))
}

/// Get the entire chain of pre-signed transactions for this derivation index out of a deposit.
#[allow(clippy::too_many_arguments)]
pub fn transaction_chain<C: secp256k1::Verification>(
    deposit_outpoint: OutPoint,
    deposit_amount: Amount,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    derivation_index: ChildNumber,
    emer_address: EmergencyAddress,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<
    (
        UnvaultTransaction,
        CancelTransactionsBatch,
        EmergencyTransaction,
        UnvaultEmergencyTransaction,
    ),
    Error,
> {
    let (unvault_tx, cancel_batch) = transaction_chain_manager(
        deposit_outpoint,
        deposit_amount,
        deposit_descriptor,
        unvault_descriptor,
        cpfp_descriptor,
        derivation_index,
        secp,
    )?;

    let der_deposit_descriptor = deposit_descriptor.derive(derivation_index, secp);
    let deposit_txin = DepositTxIn::new(
        deposit_outpoint,
        DepositTxOut::new(deposit_amount, &der_deposit_descriptor),
    );
    let emergency_tx = EmergencyTransaction::new(deposit_txin, emer_address.clone())?;

    let der_unvault_descriptor = unvault_descriptor.derive(derivation_index, secp);
    let unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
    let unvault_emergency_tx = UnvaultEmergencyTransaction::new(unvault_txin, emer_address)?;

    Ok((unvault_tx, cancel_batch, emergency_tx, unvault_emergency_tx))
}

/// Get a spend transaction out of a list of deposits and derivation indexes.
/// The derivation index used for the Spend CPFP is the highest of the deposits one.
#[allow(clippy::too_many_arguments)]
pub fn spend_tx_from_deposits<C: secp256k1::Verification>(
    deposit_txins: Vec<(OutPoint, Amount, ChildNumber)>,
    spend_txos: Vec<SpendTxOut>,
    change_txo: Option<DepositTxOut>,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    lock_time: u32,
    check_insane_fees: bool,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<SpendTransaction, TransactionCreationError> {
    let mut max_deriv_index = ChildNumber::from(0);
    let unvault_txins = deposit_txins
        .into_iter()
        .map(|(outpoint, amount, deriv_index)| {
            let der_deposit_desc = deposit_descriptor.derive(deriv_index, secp);
            let der_unvault_desc = unvault_descriptor.derive(deriv_index, secp);
            let der_cpfp_desc = cpfp_descriptor.derive(deriv_index, secp);

            let txin = DepositTxIn::new(outpoint, DepositTxOut::new(amount, &der_deposit_desc));
            if deriv_index > max_deriv_index {
                max_deriv_index = deriv_index;
            }

            UnvaultTransaction::new(txin, &der_unvault_desc, &der_cpfp_desc)
                .map(|unvault_tx| unvault_tx.spend_unvault_txin(&der_unvault_desc))
        })
        .collect::<Result<Vec<UnvaultTxIn>, TransactionCreationError>>()?;

    let der_cpfp_descriptor = cpfp_descriptor.derive(max_deriv_index, secp);
    SpendTransaction::new(
        unvault_txins,
        spend_txos,
        change_txo,
        &der_cpfp_descriptor,
        lock_time,
        check_insane_fees,
    )
}

#[cfg(any(test, feature = "fuzz"))]
pub mod tests_helpers;

#[cfg(test)]
mod tests {
    use super::tests_helpers::derive_transactions;
    use crate::{error::*, scripts::*};

    use miniscript::bitcoin::{blockdata::constants::COIN_VALUE, secp256k1, OutPoint};

    use std::str::FromStr;

    #[test]
    fn transaction_derivation() {
        let secp = secp256k1::Secp256k1::new();
        let csv = fastrand::u32(..SEQUENCE_LOCKTIME_MASK);
        eprintln!("Using a CSV of '{}'", csv);

        let deposit_prevout = OutPoint::from_str(
            "39a8212c6a9b467680d43e47b61b8363fe1febb761f9f548eb4a432b2bc9bbec:0",
        )
        .unwrap();
        let unvaults_spent = vec![
            (
                OutPoint::from_str(
                    "0ed7dc14fe8d1364b3185fa46e940cb8e858f8de32e63f88353a2bd66eb99e2a:0",
                )
                .unwrap(),
                1_000_000,
            ),
            (
                OutPoint::from_str(
                    "23aacfca328942892bb007a86db0bf5337005f642b3c46aef50c23af03ec333a:1",
                )
                .unwrap(),
                2_897_120,
            ),
            (
                OutPoint::from_str(
                    "fccabf4077b7e44ba02378a97a84611b545c11a1ef2af16cbb6e1032aa059b1d:0",
                )
                .unwrap(),
                9_327_465_907_334,
            ),
            (
                OutPoint::from_str(
                    "71dc04303184d54e6cc2f92d843282df2854d6dd66f10081147b84aeed830ae1:0",
                )
                .unwrap(),
                234_631,
            ),
        ];
        // Test the dust limit
        assert_eq!(
            derive_transactions(
                2,
                1,
                csv,
                deposit_prevout,
                234_631,
                unvaults_spent.clone(),
                true,
                &secp
            )
            .unwrap_err()
            .to_string(),
            Error::TransactionCreation(TransactionCreationError::Dust).to_string()
        );
        // Non-minimal CSV
        derive_transactions(
            2,
            1,
            SEQUENCE_LOCKTIME_MASK + 1,
            deposit_prevout,
            600_000,
            unvaults_spent.clone(),
            true,
            &secp,
        )
        .expect_err("Unclean CSV");

        // Absolute minimum
        derive_transactions(
            2,
            1,
            csv,
            deposit_prevout,
            534_632,
            unvaults_spent.clone(),
            true,
            &secp,
        )
        .unwrap_or_else(|_| {
            panic!(
                "Tx chain with 2 stakeholders, 1 manager, {} csv, 235_250 deposit",
                csv
            )
        });
        // 1 BTC
        derive_transactions(
            8,
            3,
            csv,
            deposit_prevout,
            COIN_VALUE,
            unvaults_spent.clone(),
            true,
            &secp,
        )
        .expect(&format!(
            "Tx chain with 8 stakeholders, 3 managers, {} csv, 1_000_000 deposit",
            csv
        ));
        // 100 000 BTC
        derive_transactions(
            8,
            3,
            csv,
            deposit_prevout,
            100_000 * COIN_VALUE,
            unvaults_spent.clone(),
            true,
            &secp,
        )
        .expect(&format!(
            "Tx chain with 8 stakeholders, 3 managers, {} csv, 100_000_000_000_000 deposit",
            csv
        ));
        // 100 BTC
        derive_transactions(
            MAX_STAKEHOLDERS,
            5,
            csv,
            deposit_prevout,
            100 * COIN_VALUE,
            unvaults_spent.clone(),
            true,
            &secp,
        )
        .expect(&format!(
            "Tx chain with {} stakeholders, 5 manager, {} csv, 100_000_000_000 deposit",
            MAX_STAKEHOLDERS, csv
        ));
        // 100 BTC, no cosigning server
        derive_transactions(
            MAX_STAKEHOLDERS,
            5,
            csv,
            deposit_prevout,
            100 * COIN_VALUE,
            unvaults_spent,
            false,
            &secp,
        )
        .expect(&format!(
            "Tx chain with {} stakeholders, 5 manager, {} csv, 100_000_000_000 deposit, no cosig",
            MAX_STAKEHOLDERS, csv
        ));
    }

    // Small sanity checks, see fuzzing targets for more.
    #[cfg(feature = "use-serde")]
    #[test]
    fn test_deserialize_psbt() {
        use super::{
            CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
            UnvaultEmergencyTransaction, UnvaultTransaction,
        };
        use crate::bitcoin::consensus::encode::serialize_hex;

        let emergency_psbt_str = "\"cHNidP8BAF4CAAAAAblxjSMtT1NW43OtU7paIqVl/6bzTw5Q5xX7lsGErjsMAAAAAAD9////ARh29QUAAAAAIgAgAN1LRNfR4lsBogehEY+O7NXSAWcKOvb431xEMNY3QDYAAAAAAAEBKwDh9QUAAAAAIgAgAN1LRNfR4lsBogehEY+O7NXSAWcKOvb431xEMNY3QDYBBf0TAVghAslTGncWjnHdqiPxR0bCa47bbZ9IfacoUvOtMfezbzavIQJOoGnPoDCo/yIaRQyi0WbNhOBwjW9+KuyS0tXzNDOXaiEDhIEpuvcgOIYN3wvBFQs0Tfma6tvKlb94W80dUAzrvgMhAjJCk6/xHPV/zcdKEmqkAAVQmuXAyVVa4jX1PG+WIYgPIQNRzJs4CMgBDWWmmweCLf8OqoLNncEQszFWZ25aqYOEcSEDtXG6kmkdzbsLFIxb2x0iFLVokBAyaTipwn5HdpU34/8hAtiB7MFlv5uXBDBXui9tTgu6qsa2NBla4DY1G5GyuuB3IQPd8cUxIS+8niMSWK/5BXfBtCdZsPMHc1NpAvx80ZdjQFiuIgYCMkKTr/Ec9X/Nx0oSaqQABVCa5cDJVVriNfU8b5YhiA8IQohVzwoAAAAiBgJOoGnPoDCo/yIaRQyi0WbNhOBwjW9+KuyS0tXzNDOXagiO14bnCgAAACIGAslTGncWjnHdqiPxR0bCa47bbZ9IfacoUvOtMfezbzavCOEWDZEKAAAAIgYC2IHswWW/m5cEMFe6L21OC7qqxrY0GVrgNjUbkbK64HcIADRz8AoAAAAiBgNRzJs4CMgBDWWmmweCLf8OqoLNncEQszFWZ25aqYOEcQi93C9kCgAAACIGA4SBKbr3IDiGDd8LwRULNE35murbypW/eFvNHVAM674DCBdIsDYKAAAAIgYDtXG6kmkdzbsLFIxb2x0iFLVokBAyaTipwn5HdpU34/8IonEPuQoAAAAiBgPd8cUxIS+8niMSWK/5BXfBtCdZsPMHc1NpAvx80ZdjQAinqwY/CgAAAAAA\"";
        let emergency_tx: EmergencyTransaction = serde_json::from_str(&emergency_psbt_str).unwrap();
        assert_eq!(serialize_hex(emergency_tx.tx()), "0200000001b9718d232d4f5356e373ad53ba5a22a565ffa6f34f0e50e715fb96c184ae3b0c0000000000fdffffff011876f5050000000022002000dd4b44d7d1e25b01a207a1118f8eecd5d201670a3af6f8df5c4430d637403600000000");

        let unvault_psbt_str = "\"cHNidP8BAIkCAAAAAfmN22Yg3hsR6wgkPWJ3tSpO40wY5fgINkSlClxgasy7AAAAAAD9////AkANAwAAAAAAIgAgfPlPYs+3NKdo6gu1ITRhWGaZ77RL/0n3/rfdM0nHDKAwdQAAAAAAACIAIBqfyVGG6ozM3AZyeJhKeLNsjlt7AuXs89eFQSUEgx3xAAAAAAABASuIlAMAAAAAACIAIEpy7LLM5Gsjv384BJqpdhVyxzoC96snQbKN/Pl4yFqSAQjaBABHMEQCIG7ue0n/D+JrDMknOV2Up/NyLh06p2tQTHoEZAAYYoCfAiA0fZxErfzZFgLpSV/f1uvCArcXStNUnhConPYBvEmwcgFHMEQCIALfcLNVtS1zZ/AH/5JGVPlUyNGB4tAWOAvJm5DFCFkPAiAxw8oPariZ4OqNZH/PiSQytLInnsYMmzY8khNtDWS7WQFHUiED2l1MSok0kn+im8fepkDk9JJ4kmz7S7PJbLp2MHUScDshAqg1gjG67ft3qNh1U2hWCYumJvmnWsb96aAQU3BKIwiOUq4AIgICCu8X76xDyD8Eurt1XmKvjamdwezV7UxLGsoa8yfMj2cI/w6LrAoAAAAiAgKoNYIxuu37d6jYdVNoVgmLpib5p1rG/emgEFNwSiMIjgjAoMvqCgAAACICAulOlir/rBPSuqc9Z7mGFUE1ekHvzGRuDA2sjFgPGzZ+CDooLAQKAAAAIgIDncUagEr+XYCSpDykd7a6WrIa1q58GBTGSMVms8Dk/1YI0jxctQoAAAAiAgPaXUxKiTSSf6Kbx96mQOT0kniSbPtLs8lsunYwdRJwOwhMrobwCgAAAAAiAgOdxRqASv5dgJKkPKR3trpashrWrnwYFMZIxWazwOT/VgjSPFy1CgAAAAA=\"";
        let unvault_tx: UnvaultTransaction = serde_json::from_str(&unvault_psbt_str).unwrap();
        assert_eq!(serialize_hex(unvault_tx.tx()), "0200000001f98ddb6620de1b11eb08243d6277b52a4ee34c18e5f8083644a50a5c606accbb0000000000fdffffff02400d0300000000002200207cf94f62cfb734a768ea0bb5213461586699efb44bff49f7feb7dd3349c70ca030750000000000002200201a9fc95186ea8cccdc067278984a78b36c8e5b7b02e5ecf3d785412504831df100000000");

        let cancel_psbt_str = "\"cHNidP8BAF4CAAAAAQa9mxcLxWkl14cJX/shnW6eNUirrbe283Qs6JUfLv5zAAAAAAD9////AejKAgAAAAAAIgAgSnLssszkayO/fzgEmql2FXLHOgL3qydBso38+XjIWpIAAAAAAAEBK0ANAwAAAAAAIgAgfPlPYs+3NKdo6gu1ITRhWGaZ77RL/0n3/rfdM0nHDKABCP2DAQZIMEUCIQD5tszk5/+NC6DemfMoa1CZkYEP/d2hkqivM3SNn6i8kwIgfDNO+yTvLXv6GxOSekkMnQj8z4o2DgLxuiZIeuMCUMqBIQKoNYIxuu37d6jYdVNoVgmLpib5p1rG/emgEFNwSiMIjkgwRQIhAPoIO2FH9sj0gximLn7iz2g0Xw6KjPrqqBBt4X4YthbRAiBtoIgVIeG3FzTPkmwUwjvnztDqYf63FtXWIMvujYePF4EhA9pdTEqJNJJ/opvH3qZA5PSSeJJs+0uzyWy6djB1EnA7AKohA53FGoBK/l2AkqQ8pHe2ulqyGtaufBgUxkjFZrPA5P9WrFGHZHapFLNwWLHjV9Tr1X0zDpYnHUHtmi6UiKxrdqkU0SQDi68b+vSk6ukjRWyfOEHLA9OIrGyTUodnUiEC6U6WKv+sE9K6pz1nuYYVQTV6Qe/MZG4MDayMWA8bNn4hAgrvF++sQ8g/BLq7dV5ir42pncHs1e1MSxrKGvMnzI9nUq8C9V+yaAAiAgKoNYIxuu37d6jYdVNoVgmLpib5p1rG/emgEFNwSiMIjgjAoMvqCgAAACICA9pdTEqJNJJ/opvH3qZA5PSSeJJs+0uzyWy6djB1EnA7CEyuhvAKAAAAAA==\"";
        let cancel_tx: CancelTransaction = serde_json::from_str(&cancel_psbt_str).unwrap();
        assert_eq!(serialize_hex(cancel_tx.tx()), "020000000106bd9b170bc56925d787095ffb219d6e9e3548abadb7b6f3742ce8951f2efe730000000000fdffffff01e8ca0200000000002200204a72ecb2cce46b23bf7f38049aa9761572c73a02f7ab2741b28dfcf978c85a9200000000");

        let unemergency_psbt_str = "\"cHNidP8BAF4CAAAAAfeVYT6dSrDTzQekeDseTQmpQChdIx9Fm/7yvPBvdu7HAAAAAAD9////AdLKAgAAAAAAIgAgojUvLaQJe+wXmRaaDIAaYfa2HbdfCBsgMdGjuwed2F4AAAAAAAEBK0ANAwAAAAAAIgAgXA0s+qynDjinXOmpJ/Qhuj87xEB7YcLEVdz7OX5B+l8iAgI+TfqYOB5AvGLZO2C3OWNepPtB2MXltlovJy9aNEUezEcwRAIgP5ZgDmwPn1fh7jKgweTU+K0Os/vsY+kKYnScOYewCVgCIG+KZrvbn8DPDrvJQwsbMz8PF208zO2W6hIeTGswSJOYgSICAtk/sjHYB5gv7nUSr0k25UlmeCn+7ztrilD5aKBYhOZ/RzBEAiBV9TTu0tVLMTlIlBSg/Pr21pqpehOIHduNDC7NB7ewPwIgF4p8WgqEN+haJCEG0jwmmCOjiQz7EzN2H3ps6CE7yh2BAQWrIQM3WBCQMxhfyw+ncsDqRpNgRhc1S3J5E2eZkyramf/yYqxRh2R2qRT8N/OAaFe4awdH/SRrJWbCdbsgrIisa3apFM86etaiSkLAb1YEkvfBiGPhb0XZiKxsk1KHZ1IhAvI/1b7NH17PoNpLnY2BLYTBQFM7DJReEselwbrXknJaIQIYmQoDfe8y/MUX5oa8N2g2GePHXKP5+olBBjXHgsQuF1KvA7WEALJoIgYCGJkKA33vMvzFF+aGvDdoNhnjx1yj+fqJQQY1x4LELhcIwx/TKAoAAAAiBgI+TfqYOB5AvGLZO2C3OWNepPtB2MXltlovJy9aNEUezAh4xhChCgAAACIGAtk/sjHYB5gv7nUSr0k25UlmeCn+7ztrilD5aKBYhOZ/CBtBXXMKAAAAIgYC8j/Vvs0fXs+g2kudjYEthMFAUzsMlF4Sx6XButeScloI1AXIVAoAAAAiBgM3WBCQMxhfyw+ncsDqRpNgRhc1S3J5E2eZkyramf/yYgjQeHAnCgAAAAAA\"";
        let unemergency_tx: UnvaultEmergencyTransaction =
            serde_json::from_str(&unemergency_psbt_str).unwrap();
        assert_eq!(serialize_hex(unemergency_tx.tx()), "0200000001f795613e9d4ab0d3cd07a4783b1e4d09a940285d231f459bfef2bcf06f76eec70000000000fdffffff01d2ca020000000000220020a2352f2da4097bec1799169a0c801a61f6b61db75f081b2031d1a3bb079dd85e00000000");

        let spend_psbt_str = "\"cHNidP8BAIkCAAAAAdKM0NH1IfB5EqCmcrExViMrYq0YCHkfmZvTSzFoVNmJAAAAAAD9////AkANAwAAAAAAIgAgWfVjq6I2IH//GE9+5VT1A85InZCfKg9BfxCTDKdmEFUwdQAAAAAAACIAIPkvfw7mDhcLjDoAv/ciWdH+adf8/RRqXZEu2BCe9ZsUAAAAAAABASuIlAMAAAAAACIAIFyKAdGPlWYmCg7Lut2cL8DgFJiAKJItdJTyaYGQbCNWAQjbBABHMEQCIFmUwt4fnJL3eRAWqklyV3Aikc8TYwv7CrhxPRicUbU5AiB8g+ASYSGglLZleMFDh9Pi2W/FqQYwEWesor9Bv/EiQQFIMEUCIQCGvJsPxgFZtpsNRQ3VETEkDB78gcsgB4W9hkrkBXCMBgIgIDIbqQtHakOcqtl14jpPjiMVz0KO0HVJB51tvGDU/4wBR1IhAwl6ytUyWFcjWXapo8WMj2sasbgUCRx5K+F2jeGXb8d/IQJM5T/F+uoP2b/xce+xNoDZ9+6ocbz/8PSVoayx6TJnrlKuACICAkzlP8X66g/Zv/Fx77E2gNn37qhxvP/w9JWhrLHpMmeuCLhkVBQKAAAAIgICjlU/HP1v6DJ8m2Z5ANX5jZeC9cJ/Z0eakLYfzX5gX6YISNmuZwoAAAAiAgMJesrVMlhXI1l2qaPFjI9rGrG4FAkceSvhdo3hl2/HfwiILvO9CgAAACICAzkvyp9Q3knkMYAWBKeo5xcgiaoOwUdF/SQVMdYU3QtdCBxghxwKAAAAIgIDmeAIO+xbMz8grQfSwjY97Vgl7NHkVth6Z0JfrPpBaMAIsVo/DgoAAAAAIgIC640I7MqUC5FxRyF6yE8OB2aK8YojzUiyDmWrvnjn6lgIo2rccQoAAAAAcHNidP8BAGcCAAAAAVYetH70pzOUyZwutTULwN97mzGRBqx2K/u/qMstAMuxAAAAAAB6GwAAAoAyAAAAAAAAIgAg+S9/DuYOFwuMOgC/9yJZ0f5p1/z9FGpdkS7YEJ71mxSwswIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgWfVjq6I2IH//GE9+5VT1A85InZCfKg9BfxCTDKdmEFUBAwQBAAAAAQWqIQM5L8qfUN5J5DGAFgSnqOcXIImqDsFHRf0kFTHWFN0LXaxRh2R2qRSLYmchXl+UoOeURf6sOKVrNpQlfIisa3apFOlaWTA4VwFVjhhA7wAx6l1dCbTKiKxsk1KHZ1IhA5ngCDvsWzM/IK0H0sI2Pe1YJezR5FbYemdCX6z6QWjAIQKOVT8c/W/oMnybZnkA1fmNl4L1wn9nR5qQth/NfmBfplKvAnobsmgiBgJM5T/F+uoP2b/xce+xNoDZ9+6ocbz/8PSVoayx6TJnrgi4ZFQUCgAAACIGAo5VPxz9b+gyfJtmeQDV+Y2XgvXCf2dHmpC2H81+YF+mCEjZrmcKAAAAIgYDCXrK1TJYVyNZdqmjxYyPaxqxuBQJHHkr4XaN4Zdvx38IiC7zvQoAAAAiBgM5L8qfUN5J5DGAFgSnqOcXIImqDsFHRf0kFTHWFN0LXQgcYIccCgAAACIGA5ngCDvsWzM/IK0H0sI2Pe1YJezR5FbYemdCX6z6QWjACLFaPw4KAAAAACICAuuNCOzKlAuRcUcheshPDgdmivGKI81Isg5lq7545+pYCKNq3HEKAAAAAAA\"";
        let spend_tx: SpendTransaction = serde_json::from_str(&spend_psbt_str).unwrap();
        assert_eq!(serialize_hex(&spend_tx.into_tx()), "02000000000101d28cd0d1f521f07912a0a672b13156232b62ad1808791f999bd34b316854d9890000000000fdffffff02400d03000000000022002059f563aba236207fff184f7ee554f503ce489d909f2a0f417f10930ca76610553075000000000000220020f92f7f0ee60e170b8c3a00bff72259d1fe69d7fcfd146a5d912ed8109ef59b14040047304402205994c2de1f9c92f7791016aa497257702291cf13630bfb0ab8713d189c51b53902207c83e0126121a094b66578c14387d3e2d96fc5a906301167aca2bf41bff122410148304502210086bc9b0fc60159b69b0d450dd51131240c1efc81cb200785bd864ae405708c06022020321ba90b476a439caad975e23a4f8e2315cf428ed07549079d6dbc60d4ff8c0147522103097acad5325857235976a9a3c58c8f6b1ab1b814091c792be1768de1976fc77f21024ce53fc5faea0fd9bff171efb13680d9f7eea871bcfff0f495a1acb1e93267ae52ae00000000");
    }
}
