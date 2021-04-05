//! Revault transactions
//!
//! Typesafe routines to create Revault-specific Bitcoin transactions.
//!
//! We use PSBTs as defined in [bip-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
//! for data structure as well as roles distribution.

use crate::{error::*, scripts::*, txins::*, txouts::*};

use miniscript::{
    bitcoin::{
        consensus::encode::{Decodable, Encodable},
        secp256k1,
        util::{
            bip143::SigHashCache,
            bip32::ChildNumber,
            psbt::{
                Global as PsbtGlobal, Input as PsbtIn, Output as PsbtOut,
                PartiallySignedTransaction as Psbt,
            },
        },
        Address, Amount, Network, OutPoint, PublicKey as BitcoinPubKey, Script, SigHash,
        SigHashType, Transaction, Txid, Wtxid,
    },
    BitcoinSig, DescriptorTrait,
};

#[cfg(feature = "use-serde")]
use {
    serde::de::{self, Deserialize, Deserializer},
    serde::ser::{Serialize, Serializer},
};

use std::{collections::BTreeMap, convert::TryInto, fmt};

/// The value of the CPFP output in the Unvault transaction.
/// See [practical-revault](https://github.com/revault/practical-revault/blob/master/transactions.md#unvault_tx).
pub const UNVAULT_CPFP_VALUE: u64 = 30000;

/// The feerate, in sat / W, to create the unvaulting transactions with.
pub const UNVAULT_TX_FEERATE: u64 = 6;

/// The feerate, in sat / W, to create the revaulting transactions (both emergency and the
/// cancel) with.
pub const REVAULTING_TX_FEERATE: u64 = 22;

/// We refuse to create a stakeholder-pre-signed transaction that would create an output worth
/// less than this amount of sats. This is worth 30€ for 15k€/btc.
pub const DUST_LIMIT: u64 = 200_000;

/// We can't safely error for insane fees on revaulting transactions, but we can for the unvault
/// and the spend. This is 0.2BTC, or 3k€ currently.
pub const INSANE_FEES: u64 = 20_000_000;

/// This enables CSV and is easier to apply to all transactions anyways.
pub const TX_VERSION: i32 = 2;

/// Maximum weight of a transaction to be relayed.
/// https://github.com/bitcoin/bitcoin/blob/590e49ccf2af27c6c1f1e0eb8be3a4bf4d92ce8b/src/policy/policy.h#L23-L24
pub const MAX_STANDARD_TX_WEIGHT: u32 = 400_000;

/// A Revault transaction.
///
/// Wraps a rust-bitcoin PSBT and defines some BIP174 roles as methods.
/// Namely:
/// - Creator and updater
/// - Signer
/// - Finalizer
/// - Extractor and serializer
pub trait RevaultTransaction: fmt::Debug + Clone + PartialEq {
    // TODO: Eventually, we could not expose it and only have wrappers to access
    // the PSBT informations
    /// Get the inner transaction
    fn inner_tx(&self) -> &Psbt;

    // FIXME: don't expose this. Maybe a private trait?
    /// Get the inner transaction
    fn inner_tx_mut(&mut self) -> &mut Psbt;

    /// Move inner transaction out
    fn into_psbt(self) -> Psbt;

    /// Get the sighash for an input spending an internal Revault TXO.
    /// **Do not use it for fee bumping inputs, use
    /// [RevaultTransaction::signature_hash_feebump_input] instead**
    ///
    /// Will error if the input is out of bounds or the PSBT input does not contain a Witness
    /// Script (ie was already finalized).
    fn signature_hash_internal_input(
        &self,
        input_index: usize,
        sighash_type: SigHashType,
    ) -> Result<SigHash, InputSatisfactionError> {
        let psbt = self.inner_tx();
        let psbtin = psbt
            .inputs
            .get(input_index)
            .ok_or(InputSatisfactionError::OutOfBounds)?;

        let prev_txo = psbtin
            .witness_utxo
            .as_ref()
            .expect("We always set witness_txo");
        // We always create transactions' PSBT inputs with a witness_script, and this script is
        // always the script code as we always spend P2WSH outputs.
        let witscript = psbtin
            .witness_script
            .as_ref()
            .ok_or(InputSatisfactionError::MissingWitnessScript)?;
        assert!(prev_txo.script_pubkey.is_v0_p2wsh());

        // TODO: maybe cache the cache at some point (for huge spend txs)
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        Ok(cache.signature_hash(input_index, &witscript, prev_txo.value, sighash_type))
    }

    /// Get the signature hash for an externally-managed fee-bumping input.
    ///
    /// Returns `None` if the input does not exist.
    fn signature_hash_feebump_input(
        &self,
        input_index: usize,
        script_code: &Script,
        sighash_type: SigHashType,
    ) -> Result<SigHash, InputSatisfactionError> {
        let psbt = self.inner_tx();
        let psbtin = psbt
            .inputs
            .get(input_index)
            .ok_or(InputSatisfactionError::OutOfBounds)?;

        // TODO: maybe cache the cache at some point (for huge spend txs)
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_txo = psbtin
            .witness_utxo
            .as_ref()
            .expect("We always set witness_utxo");
        Ok(cache.signature_hash(input_index, &script_code, prev_txo.value, sighash_type))
    }

    /// Add a signature in order to eventually satisfy this input.
    /// Some sanity checks against the PSBT Input are done here, but no signature check.
    ///
    /// Bigger warning: **the signature is not checked for its validity**.
    ///
    /// The BIP174 Signer role.
    fn add_signature(
        &mut self,
        input_index: usize,
        pubkey: BitcoinPubKey,
        signature: BitcoinSig,
    ) -> Result<Option<Vec<u8>>, InputSatisfactionError> {
        let psbtin = self
            .inner_tx_mut()
            .inputs
            .get_mut(input_index)
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
        if let Some(witness_script) = &psbtin.witness_script {
            // Note the network is irrelevant here.
            let expected_script_pubkey =
                Address::p2wsh(witness_script, Network::Bitcoin).script_pubkey();
            assert!(
                expected_script_pubkey == prev_txo.script_pubkey,
                "We create TxOut scriptPubKey out of this exact witnessScript."
            );
        } else {
            // We only use P2WSH utxos internally. External inputs are only ever added for fee
            // bumping, for which we require P2WPKH.
            assert!(prev_txo.script_pubkey.is_v0_p2wpkh());
        }
        assert!(
            psbtin.redeem_script.is_none(),
            "We never create Psbt input with legacy txos."
        );

        // -- If a sighash type is provided, the signer must check that the sighash is acceptable.
        // If unacceptable, they must fail.
        let (sig, sighash_type) = signature;
        let expected_sighash_type = psbtin
            .sighash_type
            .expect("We always set the SigHashType in the constructor.");
        if sighash_type != expected_sighash_type {
            return Err(InputSatisfactionError::UnexpectedSighashType);
        }

        let mut rawsig = sig.serialize_der().to_vec();
        rawsig.push(sighash_type.as_u32() as u8);

        Ok(psbtin.partial_sigs.insert(pubkey, rawsig))
    }

    /// Check and satisfy the scripts, create the witnesses.
    ///
    /// The BIP174 Input Finalizer role.
    fn finalize(
        &mut self,
        ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    ) -> Result<(), Error> {
        // We could operate on a clone for state consistency in case of error. But we can only end
        // up in an inconsistent state if miniscript's interpreter checks pass but not
        // libbitcoinconsensus' one.
        let mut psbt = self.inner_tx_mut();

        miniscript::psbt::finalize(&mut psbt, ctx)
            .map_err(|e| Error::TransactionFinalisation(e.to_string()))?;

        // Miniscript's finalize does not check against libbitcoinconsensus. And we are better safe
        // than sorry when dealing with Script ...
        for i in 0..psbt.inputs.len() {
            // BIP174:
            // For each input, the Input Finalizer determines if the input has enough data to pass
            // validation.
            self.verify_input(i)?;
        }

        Ok(())
    }

    /// Check the transaction is valid (fully-signed) and can be finalized.
    /// Slighty more efficient than calling [RevaultTransaction::finalize] on a clone as it gets
    /// rid of the belt-and-suspenders checks.
    fn is_finalizable(&self, ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>) -> bool {
        miniscript::psbt::finalize(&mut self.inner_tx().clone(), ctx).is_ok()
    }

    /// Check if the transaction was already finalized.
    fn is_finalized(&self) -> bool {
        for i in self.inner_tx().inputs.iter() {
            if i.final_script_witness.is_some() {
                return true;
            }
        }

        return false;
    }

    /// Check the transaction is valid
    fn is_valid(&self, ctx: &secp256k1::Secp256k1<impl secp256k1::Verification>) -> bool {
        if !self.is_finalized() {
            return false;
        }

        // Miniscript's finalize does not check against libbitcoinconsensus. And we are better safe
        // than sorry when dealing with Script ...
        for i in 0..self.inner_tx().inputs.len() {
            if self.verify_input(i).is_err() {
                return false;
            }
        }

        miniscript::psbt::interpreter_check(&self.inner_tx(), ctx).is_ok()
    }

    /// Verify an input of the transaction against libbitcoinconsensus out of the information
    /// contained in the PSBT input.
    fn verify_input(&self, input_index: usize) -> Result<(), Error> {
        let psbtin = self
            .inner_tx()
            .inputs
            .get(input_index)
            // It's not exactly an Input satisfaction error, but hey, out of bounds.
            .ok_or(Error::InputSatisfaction(
                InputSatisfactionError::OutOfBounds,
            ))?;
        let utxo = psbtin
            .witness_utxo
            .as_ref()
            .expect("A witness_utxo is always set");
        let (prev_scriptpubkey, prev_value) = (utxo.script_pubkey.as_bytes(), utxo.value);

        bitcoinconsensus::verify(
            prev_scriptpubkey,
            prev_value,
            // FIXME: we could change this method to be verify_tx() and not clone() for each
            // input..
            self.clone().into_bitcoin_serialized().as_slice(),
            input_index,
        )
        .map_err(|e| e.into())
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
        self.inner_tx()
            .consensus_encode(&mut buff)
            .expect("We only create valid PSBT, serialization cannot fail");
        buff
    }

    /// Create a RevaultTransaction from a BIP174-serialized transaction.
    fn from_psbt_serialized(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError>;

    /// Get the BIP174-serialized (inner) transaction encoded in base64.
    fn as_psbt_string(&self) -> String {
        base64::encode(self.as_psbt_serialized())
    }

    /// Create a RevaultTransaction from a base64-encoded BIP174-serialized transaction.
    fn from_psbt_str(psbt_str: &str) -> Result<Self, TransactionSerialisationError> {
        Self::from_psbt_serialized(&base64::decode(&psbt_str)?)
    }

    /// Get the hexadecimal representation of the transaction as used by the bitcoind API.
    fn hex(&self) -> String {
        let buff = self.clone().into_bitcoin_serialized();
        let mut as_hex = String::with_capacity(buff.len() * 2);

        for byte in buff.into_iter() {
            as_hex.push_str(&format!("{:02x}", byte));
        }

        as_hex
    }

    fn fees(&self) -> u64 {
        let mut value_in: u64 = 0;
        for i in self.inner_tx().inputs.iter() {
            value_in = value_in
                .checked_add(
                    i.witness_utxo
                        .as_ref()
                        .expect("A witness utxo is always set")
                        .value,
                )
                .expect("PSBT bug: overflow while computing spent coins value");
        }

        let mut value_out: u64 = 0;
        for o in self.inner_tx().global.unsigned_tx.output.iter() {
            value_out = value_out
                .checked_add(o.value)
                .expect("PSBT bug: overflow while computing created coins value");
        }

        value_in
            .checked_sub(value_out)
            .expect("We never create a transaction with negative fees")
    }

    /// Get the inner unsigned transaction id
    fn txid(&self) -> Txid {
        self.inner_tx().global.unsigned_tx.txid()
    }

    /// Get the inner unsigned transaction hash with witness data
    fn wtxid(&self) -> Wtxid {
        self.inner_tx().global.unsigned_tx.wtxid()
    }
}

// Boilerplate for newtype declaration and small trait helpers implementation.
macro_rules! impl_revault_transaction {
    ( $transaction_name:ident, $doc_comment:meta ) => {
        #[$doc_comment]
        #[derive(Debug, Clone, PartialEq)]
        pub struct $transaction_name(Psbt);

        impl RevaultTransaction for $transaction_name {
            fn inner_tx(&self) -> &Psbt {
                &self.0
            }

            fn inner_tx_mut(&mut self) -> &mut Psbt {
                &mut self.0
            }

            fn into_psbt(self) -> Psbt {
                self.0
            }

            fn from_psbt_serialized(
                raw_psbt: &[u8],
            ) -> Result<Self, TransactionSerialisationError> {
                $transaction_name::from_raw_psbt(raw_psbt)
            }
        }

        #[cfg(feature = "use-serde")]
        impl Serialize for $transaction_name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&self.as_psbt_string())
                } else {
                    serializer.serialize_bytes(&self.as_psbt_serialized())
                }
            }
        }

        #[cfg(feature = "use-serde")]
        impl<'de> Deserialize<'de> for $transaction_name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    $transaction_name::from_psbt_str(&String::deserialize(deserializer)?)
                        .map_err(de::Error::custom)
                } else {
                    $transaction_name::from_psbt_serialized(&Vec::<u8>::deserialize(deserializer)?)
                        .map_err(de::Error::custom)
                }
            }
        }
    };
}

// Boilerplate for creating an actual (inner) transaction with a known number of prevouts / txouts.
macro_rules! create_tx {
    ( [$( ($revault_txin:expr, $sighash_type:expr) ),* $(,)?], [$($txout:expr),* $(,)?], $lock_time:expr $(,)?) => {
        Psbt {
            global: PsbtGlobal {
                unsigned_tx: Transaction {
                    version: TX_VERSION,
                    lock_time: $lock_time,
                    input: vec![$(
                        $revault_txin.unsigned_txin(),
                    )*],
                    output: vec![$(
                        $txout.clone().into_txout(),
                    )*],
                },
                version: 0,
                xpub: BTreeMap::new(),
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),
            },
            inputs: vec![$(
                PsbtIn {
                    witness_script: $revault_txin.clone().into_txout().into_witness_script(),
                    sighash_type: Some($sighash_type),
                    witness_utxo: Some($revault_txin.into_txout().into_txout()),
                    ..PsbtIn::default()
                },
            )*],
            outputs: vec![$(
                PsbtOut {
                    witness_script: $txout.into_witness_script(),
                    ..PsbtOut::default()
                },
            )*],
        }
    }
}

// Sanity check a PSBT representing a RevaultTransaction, the part common to all transactions
fn psbt_common_sanity_checks(psbt: Psbt) -> Result<Psbt, PsbtValidationError> {
    let inner_tx = &psbt.global.unsigned_tx;

    if inner_tx.version != TX_VERSION {
        return Err(PsbtValidationError::InvalidTransactionVersion(
            inner_tx.version,
        ));
    }

    let input_count = inner_tx.input.len();
    let psbt_input_count = psbt.inputs.len();
    if input_count != psbt_input_count {
        return Err(PsbtValidationError::InputCountMismatch(
            input_count,
            psbt_input_count,
        ));
    }

    let output_count = inner_tx.output.len();
    let psbt_output_count = psbt.outputs.len();
    if output_count != psbt_output_count {
        return Err(PsbtValidationError::OutputCountMismatch(
            output_count,
            psbt_output_count,
        ));
    }

    // None: unknown, Some(true): an input was final, Some(false) an input was non-final
    let mut is_final = None;
    // Record the number of coins spent by the transaction
    let mut value_in: u64 = 0;
    for input in psbt.inputs.iter() {
        // We restrict to native segwit, also for the external fee-bumping wallet.
        if input.witness_utxo.is_none() {
            return Err(PsbtValidationError::MissingWitnessUtxo(input.clone()));
        }
        let spk = &input.witness_utxo.as_ref().unwrap().script_pubkey;
        if !(spk.is_v0_p2wsh() || spk.is_v0_p2wpkh()) {
            return Err(PsbtValidationError::InvalidInputField(input.clone()));
        }

        if input.non_witness_utxo.is_some() {
            return Err(PsbtValidationError::InvalidInputField(input.clone()));
        }

        if input.redeem_script.is_some() {
            return Err(PsbtValidationError::InvalidInputField(input.clone()));
        }

        // Make sure it does not mix finalized and non-finalized inputs or final scripts
        // and non-final scripts.
        if input.final_script_witness.is_some() {
            if is_final == Some(false) || input.witness_script.is_some() {
                return Err(PsbtValidationError::PartiallyFinalized);
            }
            is_final = Some(true);
        } else {
            if is_final == Some(true) {
                return Err(PsbtValidationError::PartiallyFinalized);
            }
            is_final = Some(false);
        }

        // If the witness script is provided, it must be a sane Miniscript
        if let Some(ref script) = input.witness_script {
            let _: miniscript::Miniscript<_, miniscript::Segwitv0> =
                miniscript::Miniscript::parse(script)
                    .map_err(|_| PsbtValidationError::InvalidInWitnessScript(input.clone()))?;
        }

        // We'll then check it doesn't create more than it spends
        value_in = value_in
            .checked_add(
                input
                    .witness_utxo
                    .as_ref()
                    .expect("None checked above")
                    .value,
            )
            .ok_or(PsbtValidationError::InsaneAmounts)?;
    }

    let mut value_out: u64 = 0;
    for o in inner_tx.output.iter() {
        value_out = value_out
            .checked_add(o.value)
            .ok_or(PsbtValidationError::InsaneAmounts)?;
    }

    if value_out > value_in {
        return Err(PsbtValidationError::InsaneAmounts);
    }

    Ok(psbt)
}

fn find_revocationtx_input(inputs: &[PsbtIn]) -> Option<&PsbtIn> {
    inputs.iter().find(|i| {
        i.witness_utxo
            .as_ref()
            .map(|o| o.script_pubkey.is_v0_p2wsh())
            == Some(true)
    })
}

fn find_feebumping_input(inputs: &[PsbtIn]) -> Option<&PsbtIn> {
    inputs.iter().find(|i| {
        i.witness_utxo
            .as_ref()
            .map(|o| o.script_pubkey.is_v0_p2wpkh())
            == Some(true)
    })
}

// The Cancel, Emer and Unvault Emer are Revocation transactions
fn check_revocationtx_input(input: &PsbtIn) -> Result<(), PsbtValidationError> {
    if input.final_script_witness.is_some() {
        // Already final, sighash type and witness script are wiped
        return Ok(());
    }

    // The revocation input must indicate that it wants to be signed with ACP
    if input.sighash_type != Some(SigHashType::AllPlusAnyoneCanPay) {
        return Err(PsbtValidationError::InvalidSighashType(input.clone()));
    }

    // The revocation input must contain a valid witness script
    if let Some(ref ws) = input.witness_script {
        if Some(&ws.to_v0_p2wsh()) != input.witness_utxo.as_ref().map(|w| &w.script_pubkey) {
            return Err(PsbtValidationError::InvalidInWitnessScript(input.clone()));
        }
    } else {
        return Err(PsbtValidationError::MissingInWitnessScript(input.clone()));
    }

    Ok(())
}

// The Cancel, Emer and Unvault Emer are Revocation transactions, this checks the appended input to
// bump the feerate.
fn check_feebump_input(input: &PsbtIn) -> Result<(), PsbtValidationError> {
    if input.final_script_witness.is_some() {
        // Already final, sighash type and witness script are wiped
        return Ok(());
    }

    // The feebump input must indicate that it wants to be signed with ALL
    if input.sighash_type != Some(SigHashType::All) {
        return Err(PsbtValidationError::InvalidSighashType(input.clone()));
    }

    // The feebump input must be P2WPKH
    if input
        .witness_utxo
        .as_ref()
        .map(|u| u.script_pubkey.is_v0_p2wpkh())
        != Some(true)
    {
        return Err(PsbtValidationError::InvalidPrevoutType(input.clone()));
    }

    // And therefore must not have a witness script
    if input.witness_script.is_some() {
        return Err(PsbtValidationError::InvalidInputField(input.clone()));
    }

    Ok(())
}

impl_revault_transaction!(
    UnvaultTransaction,
    doc = "The unvaulting transaction, spending a deposit and being eventually spent by a spend transaction (if not revaulted)."
);
impl UnvaultTransaction {
    /// An unvault transaction always spends one deposit output and contains one CPFP output in
    /// addition to the unvault one.
    /// It's always created using a fixed feerate and the CPFP output value is fixed as well.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        deposit_input: DepositTxIn,
        unvault_descriptor: &DerivedUnvaultDescriptor,
        cpfp_descriptor: &DerivedCpfpDescriptor,
        lock_time: u32,
    ) -> Result<UnvaultTransaction, TransactionCreationError> {
        // First, create a dummy transaction to get its weight without Witness
        let dummy_unvault_txout = UnvaultTxOut::new(u64::MAX, unvault_descriptor);
        let dummy_cpfp_txout = CpfpTxOut::new(u64::MAX, cpfp_descriptor);
        let dummy_tx = create_tx!(
            [(deposit_input.clone(), SigHashType::All)],
            [dummy_unvault_txout, dummy_cpfp_txout],
            lock_time,
        )
        .global
        .unsigned_tx;

        // The weight of the transaction once signed will be the size of the witness-stripped
        // transaction plus the size of the single input's witness.
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(deposit_input.max_sat_weight())
            .expect("Properly-computed weights cannot overflow");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = UNVAULT_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Properly-computed weights cannot overflow");
        // Nobody wants to pay 3k€ fees if we had a bug.
        if fees > INSANE_FEES {
            return Err(TransactionCreationError::InsaneFees);
        }

        assert!(
            total_weight <= MAX_STANDARD_TX_WEIGHT as u64,
            "A single input and two outputs"
        );

        // The unvault output value is then equal to the deposit value minus the fees and the CPFP.
        let deposit_value = deposit_input.txout().txout().value;
        if fees + UNVAULT_CPFP_VALUE + DUST_LIMIT > deposit_value {
            return Err(TransactionCreationError::Dust);
        }
        let unvault_value = deposit_value - fees - UNVAULT_CPFP_VALUE; // Arithmetic checked above

        let unvault_txout = UnvaultTxOut::new(unvault_value, unvault_descriptor);
        let cpfp_txout = CpfpTxOut::new(UNVAULT_CPFP_VALUE, cpfp_descriptor);
        Ok(UnvaultTransaction(create_tx!(
            [(deposit_input, SigHashType::All)],
            [unvault_txout, cpfp_txout],
            lock_time,
        )))
    }

    fn unvault_txin(
        &self,
        unvault_descriptor: &DerivedUnvaultDescriptor,
        sequence: u32,
    ) -> UnvaultTxIn {
        let spk = unvault_descriptor.inner().script_pubkey();
        let index = self
            .inner_tx()
            .global
            .unsigned_tx
            .output
            .iter()
            .position(|txo| txo.script_pubkey == spk)
            .expect("UnvaultTransaction is always created with an Unvault txo");

        // Unwraped above
        let txo = &self.inner_tx().global.unsigned_tx.output[index];
        let prev_txout = UnvaultTxOut::new(txo.value, unvault_descriptor);
        UnvaultTxIn::new(
            OutPoint {
                txid: self.inner_tx().global.unsigned_tx.txid(),
                vout: index.try_into().expect("There are two outputs"),
            },
            prev_txout,
            sequence,
        )
    }

    /// Get the Unvault txo to be referenced in a spending transaction
    ///
    /// # Panic
    /// Will panic if passed a csv higher than
    /// [SEQUENCE_LOCKTIME_MASK](crate::scripts::SEQUENCE_LOCKTIME_MASK)
    pub fn spend_unvault_txin(&self, unvault_descriptor: &DerivedUnvaultDescriptor) -> UnvaultTxIn {
        self.unvault_txin(unvault_descriptor, unvault_descriptor.csv_value())
    }

    /// Get the Unvault txo to be referenced in a revocation transaction
    pub fn revault_unvault_txin(
        &self,
        unvault_descriptor: &DerivedUnvaultDescriptor,
    ) -> UnvaultTxIn {
        self.unvault_txin(unvault_descriptor, RBF_SEQUENCE)
    }

    /// Get the CPFP txo to be referenced in a spending transaction
    pub fn cpfp_txin(&self, cpfp_descriptor: &DerivedCpfpDescriptor) -> CpfpTxIn {
        let spk = cpfp_descriptor.inner().script_pubkey();
        let index = self
            .inner_tx()
            .global
            .unsigned_tx
            .output
            .iter()
            .position(|txo| txo.script_pubkey == spk)
            .expect("We always create UnvaultTransaction with a CPFP output");

        // Unwraped above
        let txo = &self.inner_tx().global.unsigned_tx.output[index];
        let prev_txout = CpfpTxOut::new(txo.value, cpfp_descriptor);
        CpfpTxIn::new(
            OutPoint {
                txid: self.inner_tx().global.unsigned_tx.txid(),
                vout: index.try_into().expect("There are two outputs"),
            },
            prev_txout,
        )
    }

    /// Parse an Unvault transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = psbt_common_sanity_checks(psbt)?;

        // Unvault + CPFP txos
        let output_count = psbt.global.unsigned_tx.output.len();
        if output_count != 2 {
            return Err(PsbtValidationError::InvalidOutputCount(output_count).into());
        }

        let input_count = psbt.global.unsigned_tx.input.len();
        // We for now have 1 unvault == 1 deposit
        if input_count != 1 {
            return Err(PsbtValidationError::InvalidInputCount(input_count).into());
        }
        let input = &psbt.inputs[0];
        if input.final_script_witness.is_none() {
            if input.sighash_type != Some(SigHashType::All) {
                return Err(PsbtValidationError::InvalidSighashType(input.clone()).into());
            }
            if let Some(ref ws) = input.witness_script {
                if ws.to_v0_p2wsh()
                    != input
                        .witness_utxo
                        .as_ref()
                        .expect("Check in sanity checks")
                        .script_pubkey
                {
                    return Err(PsbtValidationError::InvalidInWitnessScript(input.clone()).into());
                }
            } else {
                return Err(PsbtValidationError::MissingInWitnessScript(input.clone()).into());
            }
        }

        // We only create P2WSH txos
        for (index, psbtout) in psbt.outputs.iter().enumerate() {
            if psbtout.witness_script.is_none() {
                return Err(PsbtValidationError::MissingOutWitnessScript(psbtout.clone()).into());
            }

            if psbtout.redeem_script.is_some() {
                return Err(PsbtValidationError::InvalidOutputField(psbtout.clone()).into());
            }

            if psbt.global.unsigned_tx.output[index].script_pubkey
                != psbtout.witness_script.as_ref().unwrap().to_v0_p2wsh()
            {
                return Err(PsbtValidationError::InvalidOutWitnessScript(psbtout.clone()).into());
            }
        }

        // NOTE: the Unvault transaction cannot get larger than MAX_STANDARD_TX_WEIGHT

        Ok(UnvaultTransaction(psbt))
    }
}

impl_revault_transaction!(
    CancelTransaction,
    doc = "The transaction \"revaulting\" a spend attempt, i.e. spending the unvaulting transaction back to a deposit txo."
);
impl CancelTransaction {
    /// A cancel transaction always pays to a deposit output and spends the unvault output, and
    /// may have a fee-bumping input.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        unvault_input: UnvaultTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        deposit_descriptor: &DerivedDepositDescriptor,
        lock_time: u32,
    ) -> CancelTransaction {
        // First, create a dummy transaction to get its weight without Witness. Note that we always
        // account for the weight *without* feebump input. It pays for itself.
        let deposit_txo = DepositTxOut::new(u64::MAX, deposit_descriptor);
        let dummy_tx = create_tx!(
            [(unvault_input.clone(), SigHashType::AllPlusAnyoneCanPay)],
            [deposit_txo],
            lock_time,
        )
        .global
        .unsigned_tx;

        // The weight of the cancel transaction without a feebump input is the weight of the
        // witness-stripped transaction plus the weight required to satisfy the unvault txin
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(unvault_input.max_sat_weight())
            .expect("Properly computed weight won't overflow");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = REVAULTING_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Properly computed weight won't overflow");
        // Without the feebump input, it should not be reachable.
        debug_assert!(fees < INSANE_FEES);

        assert!(
            total_weight <= MAX_STANDARD_TX_WEIGHT as u64,
            "At most 2 inputs and single output"
        );

        // Now, get the revaulting output value out of it.
        let unvault_value = unvault_input.txout().txout().value;
        let revault_value = unvault_value
            .checked_sub(fees)
            .expect("We would not create a dust unvault txo");
        let deposit_txo = DepositTxOut::new(revault_value, deposit_descriptor);

        CancelTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!(
                [
                    (unvault_input, SigHashType::AllPlusAnyoneCanPay),
                    (feebump_input, SigHashType::All),
                ],
                [deposit_txo],
                lock_time,
            )
        } else {
            create_tx!(
                [(unvault_input, SigHashType::AllPlusAnyoneCanPay)],
                [deposit_txo],
                lock_time,
            )
        })
    }

    /// Parse a Cancel transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = psbt_common_sanity_checks(psbt)?;

        // Deposit txo
        let output_count = psbt.global.unsigned_tx.output.len();
        if output_count != 1 {
            return Err(PsbtValidationError::InvalidOutputCount(output_count).into());
        }

        // Deposit txo is P2WSH
        let output = &psbt.outputs[0];
        if output.witness_script.is_none() {
            return Err(PsbtValidationError::MissingOutWitnessScript(output.clone()).into());
        }
        if output.redeem_script.is_some() {
            return Err(PsbtValidationError::InvalidOutputField(output.clone()).into());
        }

        let input_count = psbt.global.unsigned_tx.input.len();
        if input_count > 2 {
            return Err(PsbtValidationError::InvalidInputCount(input_count).into());
        }
        if input_count > 1 {
            let input = find_feebumping_input(&psbt.inputs)
                .ok_or(PsbtValidationError::MissingFeeBumpingInput)?;
            check_feebump_input(&input)?;
        }
        let input = find_revocationtx_input(&psbt.inputs)
            .ok_or(PsbtValidationError::MissingRevocationInput)?;
        check_revocationtx_input(&input)?;

        // We only create P2WSH txos
        for (index, psbtout) in psbt.outputs.iter().enumerate() {
            if psbtout.witness_script.is_none() {
                return Err(PsbtValidationError::MissingOutWitnessScript(psbtout.clone()).into());
            }

            if psbtout.redeem_script.is_some() {
                return Err(PsbtValidationError::InvalidOutputField(psbtout.clone()).into());
            }

            if psbt.global.unsigned_tx.output[index].script_pubkey
                != psbtout.witness_script.as_ref().unwrap().to_v0_p2wsh()
            {
                return Err(PsbtValidationError::InvalidOutWitnessScript(psbtout.clone()).into());
            }
        }

        Ok(CancelTransaction(psbt))
    }
}

impl_revault_transaction!(
    EmergencyTransaction,
    doc = "The transaction spending a deposit output to The Emergency Script."
);
impl EmergencyTransaction {
    /// The first emergency transaction always spends a deposit output and pays to the Emergency
    /// Script. It may also spend an additional output for fee-bumping.
    /// Will error **only** when trying to spend a dust deposit.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        deposit_input: DepositTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        emer_address: EmergencyAddress,
        lock_time: u32,
    ) -> Result<EmergencyTransaction, TransactionCreationError> {
        // First, create a dummy transaction to get its weight without Witness. Note that we always
        // account for the weight *without* feebump input. It has to pay for itself.
        let emer_txo = EmergencyTxOut::new(emer_address.clone(), u64::MAX);
        let dummy_tx = create_tx!(
            [(deposit_input.clone(), SigHashType::AllPlusAnyoneCanPay)],
            [emer_txo],
            lock_time,
        )
        .global
        .unsigned_tx;

        // The weight of the emergency transaction without a feebump input is the weight of the
        // witness-stripped transaction plus the weight required to satisfy the deposit txin
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(deposit_input.max_sat_weight())
            .expect("Weight computation bug");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = REVAULTING_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Weight computation bug");
        // Without the feebump input, it should not be reachable.
        debug_assert!(fees < INSANE_FEES);

        assert!(
            total_weight <= MAX_STANDARD_TX_WEIGHT as u64,
            "At most 2 inputs and a single output"
        );

        // Now, get the emergency output value out of it.
        let deposit_value = deposit_input.txout().txout().value;
        let emer_value = deposit_value
            .checked_sub(fees)
            .ok_or_else(|| TransactionCreationError::Dust)?;
        let emer_txo = EmergencyTxOut::new(emer_address, emer_value);

        Ok(EmergencyTransaction(
            if let Some(feebump_input) = feebump_input {
                create_tx!(
                    [
                        (deposit_input, SigHashType::AllPlusAnyoneCanPay),
                        (feebump_input, SigHashType::All)
                    ],
                    [emer_txo],
                    lock_time,
                )
            } else {
                create_tx!(
                    [(deposit_input, SigHashType::AllPlusAnyoneCanPay)],
                    [emer_txo],
                    lock_time,
                )
            },
        ))
    }

    /// Parse an Emergency transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = psbt_common_sanity_checks(psbt)?;

        // Emergency txo
        let output_count = psbt.global.unsigned_tx.output.len();
        if output_count != 1 {
            return Err(PsbtValidationError::InvalidOutputCount(output_count).into());
        }

        let input_count = psbt.global.unsigned_tx.input.len();
        if input_count > 2 {
            return Err(PsbtValidationError::InvalidInputCount(input_count).into());
        }
        if input_count > 1 {
            let input = find_feebumping_input(&psbt.inputs)
                .ok_or(PsbtValidationError::MissingFeeBumpingInput)?;
            check_feebump_input(&input)?;
        }
        let input = find_revocationtx_input(&psbt.inputs)
            .ok_or(PsbtValidationError::MissingRevocationInput)?;
        check_revocationtx_input(&input)?;

        Ok(EmergencyTransaction(psbt))
    }
}

impl_revault_transaction!(
    UnvaultEmergencyTransaction,
    doc = "The transaction spending an unvault output to The Emergency Script."
);
impl UnvaultEmergencyTransaction {
    /// The second emergency transaction always spends an unvault output and pays to the Emergency
    /// Script. It may also spend an additional output for fee-bumping.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        unvault_input: UnvaultTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        emer_address: EmergencyAddress,
        lock_time: u32,
    ) -> UnvaultEmergencyTransaction {
        // First, create a dummy transaction to get its weight without Witness. Note that we always
        // account for the weight *without* feebump input. It has to pay for itself.
        let emer_txo = EmergencyTxOut::new(emer_address.clone(), u64::MAX);
        let dummy_tx = create_tx!(
            [(unvault_input.clone(), SigHashType::AllPlusAnyoneCanPay)],
            [emer_txo],
            lock_time,
        )
        .global
        .unsigned_tx;

        // The weight of the unvault emergency transaction without a feebump input is the weight of
        // the witness-stripped transaction plus the weight required to satisfy the unvault txin
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(unvault_input.max_sat_weight())
            .expect("Weight computation bug");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = REVAULTING_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Weight computation bug");
        // Without the feebump input, it should not be reachable.
        debug_assert!(fees < INSANE_FEES);

        assert!(
            total_weight <= MAX_STANDARD_TX_WEIGHT as u64,
            "At most 2 inputs and a single output"
        );

        // Now, get the emergency output value out of it.
        let deposit_value = unvault_input.txout().txout().value;
        let emer_value = deposit_value
            .checked_sub(fees)
            .expect("We would never create a dust unvault txo");
        let emer_txo = EmergencyTxOut::new(emer_address, emer_value);

        UnvaultEmergencyTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!(
                [
                    (unvault_input, SigHashType::AllPlusAnyoneCanPay),
                    (feebump_input, SigHashType::All)
                ],
                [emer_txo],
                lock_time,
            )
        } else {
            create_tx!(
                [(unvault_input, SigHashType::AllPlusAnyoneCanPay)],
                [emer_txo],
                lock_time,
            )
        })
    }

    /// Parse an UnvaultEmergency transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = psbt_common_sanity_checks(psbt)?;

        // Emergency txo
        let output_count = psbt.global.unsigned_tx.output.len();
        if output_count != 1 {
            return Err(PsbtValidationError::InvalidOutputCount(output_count).into());
        }

        let input_count = psbt.global.unsigned_tx.input.len();
        if input_count > 2 {
            return Err(PsbtValidationError::InvalidInputCount(input_count).into());
        }
        if input_count > 1 {
            let input = find_feebumping_input(&psbt.inputs)
                .ok_or(PsbtValidationError::MissingFeeBumpingInput)?;
            check_feebump_input(&input)?;
        }
        let input = find_revocationtx_input(&psbt.inputs)
            .ok_or(PsbtValidationError::MissingRevocationInput)?;
        check_revocationtx_input(&input)?;

        Ok(UnvaultEmergencyTransaction(psbt))
    }
}

impl_revault_transaction!(
    SpendTransaction,
    doc = "The transaction spending the unvaulting transaction, paying to one or multiple \
    externally-controlled addresses, and possibly to a new deposit txo for the change."
);
impl SpendTransaction {
    /// A spend transaction can batch multiple unvault txouts, and may have any number of
    /// txouts (destination and change) in addition to the CPFP one..
    ///
    /// The insane fees check is gated behind the `insane_fee_checks` parameter as the caller
    /// may want to create a transaction without a change output.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        unvault_inputs: Vec<UnvaultTxIn>,
        spend_txouts: Vec<SpendTxOut>,
        cpfp_descriptor: &DerivedCpfpDescriptor,
        lock_time: u32,
        insane_fee_check: bool,
    ) -> Result<SpendTransaction, TransactionCreationError> {
        // The CPFP is tricky to compute. We could be smart and avoid some allocations here
        // but at the cost of clarity.
        let cpfp_txo = SpendTransaction::cpfp_txout(
            unvault_inputs.clone(),
            spend_txouts.clone(),
            cpfp_descriptor,
            lock_time,
        );

        // Used later to check the maximum transaction size.
        let sat_weight = unvault_inputs
            .iter()
            .map(|txin| txin.max_sat_weight())
            .sum::<usize>();

        // Record the value spent
        let mut value_in: u64 = 0;

        let mut txos = Vec::with_capacity(spend_txouts.len() + 1);
        txos.push(cpfp_txo.txout().clone());
        txos.extend(spend_txouts.iter().map(|spend_txout| match spend_txout {
            SpendTxOut::Destination(ref txo) => txo.clone().into_txout(),
            SpendTxOut::Change(ref txo) => txo.clone().into_txout(),
        }));

        // For the PsbtOut s
        let mut txos_wit_script = Vec::with_capacity(spend_txouts.len() + 1);
        txos_wit_script.push(cpfp_txo.into_witness_script());
        txos_wit_script.extend(
            spend_txouts
                .into_iter()
                .map(|spend_txout| match spend_txout {
                    SpendTxOut::Destination(txo) => txo.into_witness_script(), // None
                    SpendTxOut::Change(txo) => txo.into_witness_script(),
                }),
        );

        let psbt = Psbt {
            global: PsbtGlobal {
                unsigned_tx: Transaction {
                    version: TX_VERSION,
                    lock_time,
                    input: unvault_inputs
                        .iter()
                        .map(|input| input.unsigned_txin())
                        .collect(),
                    output: txos,
                },
                version: 0,
                xpub: BTreeMap::new(),
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),
            },
            inputs: unvault_inputs
                .into_iter()
                .map(|input| {
                    let prev_txout = input.into_txout();
                    value_in += prev_txout.txout().value;
                    PsbtIn {
                        witness_script: prev_txout.witness_script().clone(),
                        sighash_type: Some(SigHashType::All), // Unvault spends are always signed with ALL
                        witness_utxo: Some(prev_txout.into_txout()),
                        ..PsbtIn::default()
                    }
                })
                .collect(),
            outputs: txos_wit_script
                .into_iter()
                .map(|witness_script| PsbtOut {
                    witness_script,
                    ..PsbtOut::default()
                })
                .collect(),
        };

        // Make sure we didn't create a Monster Tx :tm: ..
        let unsigned_tx = &psbt.global.unsigned_tx;
        let witstrip_weight = unsigned_tx.get_weight();
        let total_weight = sat_weight
            .checked_add(witstrip_weight)
            .expect("Weight computation bug: cannot overflow");
        if total_weight > MAX_STANDARD_TX_WEIGHT as usize {
            return Err(TransactionCreationError::TooLarge);
        }

        let value_out: u64 = unsigned_tx.output.iter().map(|o| o.value).sum();
        let fees = value_in
            .checked_sub(value_out)
            .ok_or(TransactionCreationError::NegativeFees)?;
        if insane_fee_check && fees > INSANE_FEES {
            return Err(TransactionCreationError::InsaneFees);
        }

        Ok(SpendTransaction(psbt))
    }

    /// Get the CPFP transaction output for a Spend transaction spending these `unvault_inputs`
    /// and creating these `spend_txouts`.
    ///
    /// The CPFP output value is dependant on the transaction size, see [practical-revaul
    /// t](https://github.com/revault/practical-revault/blob/master/transactions.md#spend_tx) for
    /// more details.
    pub fn cpfp_txout(
        unvault_inputs: Vec<UnvaultTxIn>,
        spend_txouts: Vec<SpendTxOut>,
        cpfp_descriptor: &DerivedCpfpDescriptor,
        lock_time: u32,
    ) -> CpfpTxOut {
        let mut txos = Vec::with_capacity(spend_txouts.len() + 1);
        let dummy_cpfp_txo = CpfpTxOut::new(u64::MAX, &cpfp_descriptor);
        txos.push(dummy_cpfp_txo.txout().clone());
        txos.extend(spend_txouts.iter().map(|spend_txout| match spend_txout {
            SpendTxOut::Destination(ref txo) => txo.clone().into_txout(),
            SpendTxOut::Change(ref txo) => txo.clone().into_txout(),
        }));
        let dummy_tx = Transaction {
            version: TX_VERSION,
            lock_time,
            input: unvault_inputs
                .iter()
                .map(|input| input.unsigned_txin())
                .collect(),
            output: txos,
        };

        let sat_weight: u64 = unvault_inputs
            .iter()
            .map(|txin| txin.max_sat_weight())
            .sum::<usize>()
            .try_into()
            .expect("An usize doesn't fit in an u64?");
        let witstrip_weight: u64 = dummy_tx
            .get_weight()
            .try_into()
            .expect("Bug: an usize that doesn't fit in a u64?");
        let total_weight = sat_weight
            .checked_add(witstrip_weight)
            .expect("Weight computation bug: cannot overflow");

        // See https://github.com/revault/practical-revault/blob/master/transactions.md#spend_tx
        // for this arbirtrary value.
        let cpfp_value = 16 * total_weight;
        CpfpTxOut::new(cpfp_value, &cpfp_descriptor)
    }

    /// Get the feerate of this transaction, assuming fully-satisfied inputs. If the transaction
    /// is already finalized, returns the exact feerate. Otherwise computes the maximum reasonable
    /// weight of a satisfaction and returns the feerate based on this estimation.
    pub fn max_feerate(&self) -> u64 {
        let fees = self.fees();
        let weight = self.max_weight();

        fees.checked_add(weight - 1) // Weight is never 0
            .expect("Feerate computation bug, fees >u64::MAX")
            .checked_div(weight)
            .expect("Weight is never 0")
    }

    /// Get the size of this transaction, assuming fully-satisfied inputs. If the transaction
    /// is already finalized, returns the exact size in witness units. Otherwise computes the
    /// maximum reasonable weight of a satisfaction.
    pub fn max_weight(&self) -> u64 {
        let psbt = self.inner_tx();
        let tx = &psbt.global.unsigned_tx;

        let mut weight: u64 = tx.get_weight().try_into().expect("Can't be >u64::MAX");
        for txin in psbt.inputs.iter() {
            let txin_weight: u64 = if self.is_finalized() {
                txin.final_script_witness
                    .as_ref()
                    .expect("Always set if final")
                    .iter()
                    .map(|e| e.len())
                    .sum::<usize>()
                    .try_into()
                    .expect("Bug: witness size >u64::MAX")
            } else {
                miniscript::descriptor::Wsh::new(
                    miniscript::Miniscript::parse(
                        txin.witness_script
                            .as_ref()
                            .expect("Unvault txins always have a witness Script"),
                    )
                    .expect("UnvaultTxIn witness_script is created from a Miniscript"),
                )
                .expect("")
                .max_satisfaction_weight()
                .expect("It's a sane Script, derived from a Miniscript")
                .try_into()
                .expect("Can't be >u64::MAX")
            };
            weight = weight
                .checked_add(txin_weight)
                .expect("Weight computation bug: overflow computing spent coins value");
        }
        assert!(weight > 0, "We never create an empty tx");

        weight
    }

    // FIXME: feerate sanity checks
    /// Parse a Spend transaction from a PSBT
    pub fn from_raw_psbt(raw_psbt: &[u8]) -> Result<Self, TransactionSerialisationError> {
        let psbt = Decodable::consensus_decode(raw_psbt)?;
        let psbt = psbt_common_sanity_checks(psbt)?;

        if psbt.inputs.len() < 1 {
            return Err(PsbtValidationError::InvalidInputCount(0).into());
        }

        let mut max_sat_weight = 0;
        for input in psbt.inputs.iter() {
            if input.final_script_witness.is_some() {
                continue;
            }

            if input.sighash_type != Some(SigHashType::All) {
                return Err(PsbtValidationError::InvalidSighashType(input.clone()).into());
            }

            // The revocation input must contain a valid witness script
            if let Some(ref ws) = input.witness_script {
                if Some(&ws.to_v0_p2wsh()) != input.witness_utxo.as_ref().map(|w| &w.script_pubkey)
                {
                    return Err(PsbtValidationError::InvalidInWitnessScript(input.clone()).into());
                }
            } else {
                return Err(PsbtValidationError::MissingInWitnessScript(input.clone()).into());
            }

            max_sat_weight += miniscript::descriptor::Wsh::new(
                miniscript::Miniscript::parse(
                    input
                        .witness_script
                        .as_ref()
                        .ok_or_else(|| PsbtValidationError::InvalidInputField(input.clone()))?,
                )
                .map_err(|_| PsbtValidationError::InvalidInputField(input.clone()))?,
            )
            .map_err(|_| PsbtValidationError::InvalidInputField(input.clone()))?
            .max_satisfaction_weight()
            .map_err(|_| PsbtValidationError::InvalidInputField(input.clone()))?;
        }

        // Make sure the transaction cannot get out of standardness bounds once finalized
        let spend_tx = SpendTransaction(psbt);
        let witstrip_weight = spend_tx.inner_tx().global.unsigned_tx.get_weight();
        let total_weight = witstrip_weight
            .checked_add(max_sat_weight)
            .expect("Weight computation bug");
        if total_weight > MAX_STANDARD_TX_WEIGHT as usize {
            return Err(PsbtValidationError::TransactionTooLarge.into());
        }

        Ok(spend_tx)
    }
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

        DepositTxIn::new(outpoint, DepositTxOut::new(txo.value, deposit_descriptor))
    }
}

/// The fee-bumping transaction, we don't create nor sign it.
#[derive(Debug, Clone, PartialEq)]
pub struct FeeBumpTransaction(pub Transaction);

/// Get the chain of pre-signed transaction out of a deposit available for a manager.
/// No feebump input.
pub fn transaction_chain_manager<C: secp256k1::Verification>(
    deposit_outpoint: OutPoint,
    deposit_amount: Amount,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    derivation_index: ChildNumber,
    lock_time: u32,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<(UnvaultTransaction, CancelTransaction), Error> {
    let (der_deposit_descriptor, der_unvault_descriptor, der_cpfp_descriptor) = (
        deposit_descriptor.derive(derivation_index, secp),
        unvault_descriptor.derive(derivation_index, secp),
        cpfp_descriptor.derive(derivation_index, secp),
    );

    let deposit_txin = DepositTxIn::new(
        deposit_outpoint,
        DepositTxOut::new(deposit_amount.as_sat(), &der_deposit_descriptor),
    );
    let unvault_tx = UnvaultTransaction::new(
        deposit_txin,
        &der_unvault_descriptor,
        &der_cpfp_descriptor,
        lock_time,
    )?;

    let cancel_tx = CancelTransaction::new(
        unvault_tx.revault_unvault_txin(&der_unvault_descriptor),
        None,
        &der_deposit_descriptor,
        lock_time,
    );

    Ok((unvault_tx, cancel_tx))
}

/// Get the entire chain of pre-signed transaction for this derivation index out of a deposit. No feebump input.
pub fn transaction_chain<C: secp256k1::Verification>(
    deposit_outpoint: OutPoint,
    deposit_amount: Amount,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    derivation_index: ChildNumber,
    emer_address: EmergencyAddress,
    lock_time: u32,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<
    (
        UnvaultTransaction,
        CancelTransaction,
        EmergencyTransaction,
        UnvaultEmergencyTransaction,
    ),
    Error,
> {
    let (unvault_tx, cancel_tx) = transaction_chain_manager(
        deposit_outpoint,
        deposit_amount,
        deposit_descriptor,
        unvault_descriptor,
        cpfp_descriptor,
        derivation_index,
        lock_time,
        secp,
    )?;

    let der_deposit_descriptor = deposit_descriptor.derive(derivation_index, secp);
    let deposit_txin = DepositTxIn::new(
        deposit_outpoint,
        DepositTxOut::new(deposit_amount.as_sat(), &der_deposit_descriptor),
    );
    let emergency_tx =
        EmergencyTransaction::new(deposit_txin, None, emer_address.clone(), lock_time)?;

    let der_unvault_descriptor = unvault_descriptor.derive(derivation_index, secp);
    let unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
    let unvault_emergency_tx =
        UnvaultEmergencyTransaction::new(unvault_txin, None, emer_address, lock_time);

    Ok((unvault_tx, cancel_tx, emergency_tx, unvault_emergency_tx))
}

/// Get a spend transaction out of a list of deposits and derivation indexes.
/// The derivation index used for the Spend CPFP is the highest of the deposits one.
pub fn spend_tx_from_deposits<C: secp256k1::Verification>(
    deposit_txins: Vec<(OutPoint, Amount, ChildNumber)>,
    spend_txos: Vec<SpendTxOut>,
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

            let txin = DepositTxIn::new(
                outpoint,
                DepositTxOut::new(amount.as_sat(), &der_deposit_desc),
            );
            if deriv_index > max_deriv_index {
                max_deriv_index = deriv_index;
            }

            UnvaultTransaction::new(txin, &der_unvault_desc, &der_cpfp_desc, lock_time)
                .and_then(|unvault_tx| Ok(unvault_tx.spend_unvault_txin(&der_unvault_desc)))
        })
        .collect::<Result<Vec<UnvaultTxIn>, TransactionCreationError>>()?;

    let der_cpfp_descriptor = cpfp_descriptor.derive(max_deriv_index, secp);
    SpendTransaction::new(
        unvault_txins,
        spend_txos,
        &der_cpfp_descriptor,
        lock_time,
        check_insane_fees,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        transaction_chain, CancelTransaction, DepositTransaction, EmergencyAddress,
        EmergencyTransaction, FeeBumpTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    };
    use crate::{error::*, scripts::*, txins::*, txouts::*};

    use std::{iter::repeat_with, str::FromStr};

    use miniscript::{
        bitcoin::{
            secp256k1, util::bip32, Address, Amount, Network, OutPoint, SigHash, SigHashType,
            Transaction, TxIn, TxOut,
        },
        descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
        Descriptor, DescriptorTrait,
    };

    fn get_random_privkey(rng: &mut fastrand::Rng) -> bip32::ExtendedPrivKey {
        let rand_bytes: Vec<u8> = repeat_with(|| rng.u8(..)).take(64).collect();

        bip32::ExtendedPrivKey::new_master(Network::Bitcoin, &rand_bytes)
            .unwrap_or_else(|_| get_random_privkey(rng))
    }

    /// This generates the master private keys to derive directly from master, so it's
    /// [None]<xpub_goes_here>m/* descriptor pubkeys
    fn get_participants_sets(
        n_stk: usize,
        n_man: usize,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
    ) -> (
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
    ) {
        let mut rng = fastrand::Rng::new();

        let managers_priv = (0..n_man)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let managers = managers_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: None,
                    xkey: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    wildcard: Wildcard::Unhardened,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        let stakeholders_priv = (0..n_stk)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let stakeholders = stakeholders_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: None,
                    xkey: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    wildcard: Wildcard::Unhardened,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        let cosigners_priv = (0..n_stk)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let cosigners = cosigners_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: None,
                    xkey: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    wildcard: Wildcard::Unhardened,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        (
            (managers_priv, managers),
            (stakeholders_priv, stakeholders),
            (cosigners_priv, cosigners),
        )
    }

    // Routine for ""signing"" a transaction
    fn satisfy_transaction_input(
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        tx: &mut impl RevaultTransaction,
        input_index: usize,
        tx_sighash: &SigHash,
        xprivs: &Vec<bip32::ExtendedPrivKey>,
        child_number: Option<bip32::ChildNumber>,
        sighash_type: SigHashType,
    ) -> Result<(), Error> {
        // Can we agree that rustfmt does some nasty formatting now ??
        let derivation_path = bip32::DerivationPath::from(if let Some(cn) = child_number {
            vec![cn]
        } else {
            vec![]
        });

        for xpriv in xprivs {
            let sig = (
                secp.sign(
                    &secp256k1::Message::from_slice(&tx_sighash).unwrap(),
                    &xpriv
                        .derive_priv(&secp, &derivation_path)
                        .unwrap()
                        .private_key
                        .key,
                ),
                sighash_type,
            );

            let xpub = DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: bip32::ExtendedPubKey::from_private(&secp, xpriv),
                derivation_path: bip32::DerivationPath::from(vec![]),
                wildcard: if child_number.is_some() {
                    Wildcard::Unhardened
                } else {
                    Wildcard::None
                },
            });
            let key = if let Some(index) = child_number {
                xpub.derive(index.into())
            } else {
                xpub
            }
            .derive_public_key(secp)
            .unwrap();

            tx.add_signature(input_index, key, sig)?;
        }

        Ok(())
    }

    #[test]
    fn transaction_derivation() {
        let secp = secp256k1::Secp256k1::new();
        let csv = fastrand::u32(..SEQUENCE_LOCKTIME_MASK);
        eprintln!("Using a CSV of '{}'", csv);

        // Test the dust limit
        assert_eq!(
            derive_transactions(2, 1, csv, 234_631, &secp)
                .unwrap_err()
                .to_string(),
            Error::TransactionCreation(TransactionCreationError::Dust).to_string()
        );
        // Non-minimal CSV
        derive_transactions(2, 1, SEQUENCE_LOCKTIME_MASK + 1, 300_000, &secp)
            .expect_err("Unclean CSV");

        // Absolute minimum
        derive_transactions(2, 1, csv, 234_632, &secp).expect(&format!(
            "Tx chain with 2 stakeholders, 1 manager, {} csv, 235_250 deposit",
            csv
        ));
        // 1 BTC
        derive_transactions(8, 3, csv, 100_000_000, &secp).expect(&format!(
            "Tx chain with 8 stakeholders, 3 managers, {} csv, 1_000_000 deposit",
            csv
        ));
        // 100 000 BTC
        derive_transactions(8, 3, csv, 100_000_000_000_000, &secp).expect(&format!(
            "Tx chain with 8 stakeholders, 3 managers, {} csv, 100_000_000_000_000 deposit",
            csv
        ));
        // 100 BTC
        derive_transactions(38, 5, csv, 100_000_000_000, &secp).expect(&format!(
            "Tx chain with 38 stakeholders, 5 manager, {} csv, 100_000_000_000 deposit",
            csv
        ));
    }

    fn derive_transactions(
        n_stk: usize,
        n_man: usize,
        csv: u32,
        deposit_value: u64,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
    ) -> Result<(), Error> {
        // Let's get the 10th key of each
        let child_number = bip32::ChildNumber::from(10);

        // Keys, keys, keys everywhere !
        let (
            (managers_priv, managers),
            (stakeholders_priv, stakeholders),
            (cosigners_priv, cosigners),
        ) = get_participants_sets(n_stk, n_man, secp);

        // Get the script descriptors for the txos we're going to create
        let unvault_descriptor = UnvaultDescriptor::new(
            stakeholders.clone(),
            managers.clone(),
            managers.len(),
            cosigners.clone(),
            csv,
        )?;
        assert_eq!(unvault_descriptor.csv_value(), csv);
        let cpfp_descriptor =
            CpfpDescriptor::new(managers).expect("Unvault CPFP descriptor generation error");
        let deposit_descriptor =
            DepositDescriptor::new(stakeholders).expect("Deposit descriptor generation error");

        // We reuse the deposit descriptor for the emergency address
        let emergency_address = EmergencyAddress::from(Address::p2wsh(
            &deposit_descriptor
                .derive(child_number, secp)
                .inner()
                .explicit_script(),
            Network::Bitcoin,
        ))
        .expect("It's a P2WSH");

        let der_deposit_descriptor = deposit_descriptor.derive(child_number, secp);
        let der_unvault_descriptor = unvault_descriptor.derive(child_number, secp);
        assert_eq!(
            der_unvault_descriptor.csv_value(),
            unvault_descriptor.csv_value()
        );
        let der_cpfp_descriptor = cpfp_descriptor.derive(child_number, secp);

        // The funding transaction does not matter (random txid from my mempool)
        let deposit_scriptpubkey = der_deposit_descriptor.inner().script_pubkey();
        let deposit_raw_tx = Transaction {
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
                value: deposit_value,
                script_pubkey: deposit_scriptpubkey.clone(),
            }],
        };
        let deposit_txo =
            DepositTxOut::new(deposit_raw_tx.output[0].value, &der_deposit_descriptor);
        let deposit_tx = DepositTransaction(deposit_raw_tx);
        let deposit_outpoint = OutPoint {
            txid: deposit_tx.0.txid(),
            vout: 0,
        };
        let deposit_txin = DepositTxIn::new(deposit_outpoint, deposit_txo.clone());

        // Test that the transaction helper(s) derive the same transactions as we do
        let (h_unvault, h_cancel, h_emer, h_unemer) = transaction_chain(
            deposit_outpoint,
            Amount::from_sat(deposit_txo.txout().value),
            &deposit_descriptor,
            &unvault_descriptor,
            &cpfp_descriptor,
            child_number,
            emergency_address.clone(),
            0,
            secp,
        )?;

        // The fee-bumping utxo, used in revaulting transactions inputs to bump their feerate.
        // We simulate a wallet utxo.
        let mut rng = fastrand::Rng::new();
        let feebump_xpriv = get_random_privkey(&mut rng);
        let feebump_xpub = bip32::ExtendedPubKey::from_private(&secp, &feebump_xpriv);
        let feebump_descriptor = Descriptor::new_wpkh(
            DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: feebump_xpub,
                derivation_path: bip32::DerivationPath::from(vec![]),
                wildcard: Wildcard::None, // We are not going to derive from this one
            })
            .derive_public_key(secp)
            .unwrap(),
        )
        .unwrap();
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
        let feebump_txo =
            FeeBumpTxOut::new(raw_feebump_tx.output[0].clone()).expect("It is a p2wpkh");
        let feebump_tx = FeeBumpTransaction(raw_feebump_tx);

        // Create and sign the first (deposit) emergency transaction
        // We can sign the transaction without the feebump input
        let mut emergency_tx_no_feebump =
            EmergencyTransaction::new(deposit_txin.clone(), None, emergency_address.clone(), 0)
                .unwrap();
        assert_eq!(h_emer, emergency_tx_no_feebump);

        // 376 is the witstrip weight of an emer tx (1 segwit input, 1 P2WSH txout), 22 is the feerate is sat/WU
        assert_eq!(
            emergency_tx_no_feebump.fees(),
            (376 + deposit_txin.max_sat_weight() as u64) * 22,
        );
        // We cannot get a sighash for a non-existing input
        assert_eq!(
            emergency_tx_no_feebump
                .signature_hash_internal_input(10, SigHashType::AllPlusAnyoneCanPay),
            Err(InputSatisfactionError::OutOfBounds)
        );
        // But for an existing one, all good
        let emergency_tx_sighash_vault = emergency_tx_no_feebump
            .signature_hash_internal_input(0, SigHashType::AllPlusAnyoneCanPay)
            .expect("Input exists");
        // We can't force it to accept a SIGHASH_ALL signature:
        let err = satisfy_transaction_input(
            &secp,
            &mut emergency_tx_no_feebump,
            0,
            &emergency_tx_sighash_vault,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::All,
        );
        assert_eq!(
            err.unwrap_err().to_string(),
            Error::InputSatisfaction(InputSatisfactionError::UnexpectedSighashType).to_string()
        );
        // Now, that's the right SIGHASH
        satisfy_transaction_input(
            &secp,
            &mut emergency_tx_no_feebump,
            0,
            &emergency_tx_sighash_vault,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
        // Without feebump it finalizes just fine
        emergency_tx_no_feebump.finalize(&secp)?;

        let feebump_txin = FeeBumpTxIn::new(
            OutPoint {
                txid: feebump_tx.0.txid(),
                vout: 0,
            },
            feebump_txo.clone(),
        );
        let mut emergency_tx = EmergencyTransaction::new(
            deposit_txin.clone(),
            Some(feebump_txin),
            emergency_address.clone(),
            0,
        )
        .unwrap();
        let emergency_tx_sighash_feebump = emergency_tx
            .signature_hash_feebump_input(1, &feebump_descriptor.script_code(), SigHashType::All)
            .expect("Input exists");
        satisfy_transaction_input(
            &secp,
            &mut emergency_tx,
            0,
            // This sighash was created without knowledge of the feebump input. It's fine.
            &emergency_tx_sighash_vault,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
        satisfy_transaction_input(
            &secp,
            &mut emergency_tx,
            1,
            &emergency_tx_sighash_feebump,
            &vec![feebump_xpriv],
            None,
            SigHashType::All,
        )?;
        emergency_tx.finalize(&secp)?;

        // Create but don't sign the unvaulting transaction until all revaulting transactions
        // are finalized
        let deposit_txin_sat_cost = deposit_txin.max_sat_weight();
        let mut unvault_tx = UnvaultTransaction::new(
            deposit_txin.clone(),
            &der_unvault_descriptor,
            &der_cpfp_descriptor,
            0,
        )?;

        assert_eq!(h_unvault, unvault_tx);
        let unvault_value = unvault_tx.inner_tx().global.unsigned_tx.output[0].value;
        // 548 is the witstrip weight of an unvault tx (1 segwit input, 2 P2WSH txouts), 6 is the
        // feerate is sat/WU, and 30_000 is the CPFP output value.
        assert_eq!(unvault_tx.fees(), (548 + deposit_txin_sat_cost as u64) * 6);

        // Create and sign the cancel transaction
        let rev_unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
        assert_eq!(rev_unvault_txin.txout().txout().value, unvault_value);
        // We can create it entirely without the feebump input
        let mut cancel_tx_without_feebump =
            CancelTransaction::new(rev_unvault_txin.clone(), None, &der_deposit_descriptor, 0);
        assert_eq!(h_cancel, cancel_tx_without_feebump);
        // Keep track of the fees we computed..
        let value_no_feebump = cancel_tx_without_feebump
            .inner_tx()
            .global
            .unsigned_tx
            .output[0]
            .value;
        // 376 is the witstrip weight of a cancel tx (1 segwit input, 1 P2WSH txout), 22 is the feerate is sat/WU
        assert_eq!(
            cancel_tx_without_feebump.fees(),
            (376 + rev_unvault_txin.max_sat_weight() as u64) * 22,
        );
        let cancel_tx_without_feebump_sighash = cancel_tx_without_feebump
            .signature_hash_internal_input(0, SigHashType::AllPlusAnyoneCanPay)
            .expect("Input exists");
        satisfy_transaction_input(
            &secp,
            &mut cancel_tx_without_feebump,
            0,
            &cancel_tx_without_feebump_sighash,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
        cancel_tx_without_feebump.finalize(&secp).unwrap();
        // We can reuse the ANYONE_ALL sighash for the one with the feebump input
        let feebump_txin = FeeBumpTxIn::new(
            OutPoint {
                txid: feebump_tx.0.txid(),
                vout: 0,
            },
            feebump_txo.clone(),
        );
        let mut cancel_tx = CancelTransaction::new(
            rev_unvault_txin.clone(),
            Some(feebump_txin),
            &der_deposit_descriptor,
            0,
        );
        // It really is a belt-and-suspenders check as the sighash would differ too.
        assert_eq!(
            cancel_tx_without_feebump
                .inner_tx()
                .global
                .unsigned_tx
                .output[0]
                .value,
            value_no_feebump,
            "Base fees when computing with with feebump differ !!"
        );
        let cancel_tx_sighash_feebump = cancel_tx
            .signature_hash_feebump_input(1, &feebump_descriptor.script_code(), SigHashType::All)
            .expect("Input exists");
        satisfy_transaction_input(
            &secp,
            &mut cancel_tx,
            0,
            &cancel_tx_without_feebump_sighash,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
        satisfy_transaction_input(
            &secp,
            &mut cancel_tx,
            1,
            &cancel_tx_sighash_feebump,
            &vec![feebump_xpriv],
            None, // No derivation path for the feebump key
            SigHashType::All,
        )?;
        cancel_tx.finalize(&secp)?;

        // We can create it without the feebump input
        let mut unemergency_tx_no_feebump = UnvaultEmergencyTransaction::new(
            rev_unvault_txin.clone(),
            None,
            emergency_address.clone(),
            0,
        );
        assert_eq!(h_unemer, unemergency_tx_no_feebump);
        // 376 is the witstrip weight of an emer tx (1 segwit input, 1 P2WSH txout), 22 is the feerate is sat/WU
        assert_eq!(
            unemergency_tx_no_feebump.fees(),
            (376 + rev_unvault_txin.max_sat_weight() as u64) * 22,
        );
        let unemergency_tx_sighash = unemergency_tx_no_feebump
            .signature_hash_internal_input(0, SigHashType::AllPlusAnyoneCanPay)
            .expect("Input exists");
        satisfy_transaction_input(
            &secp,
            &mut unemergency_tx_no_feebump,
            0,
            &unemergency_tx_sighash,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
        unemergency_tx_no_feebump.finalize(&secp)?;

        let feebump_txin = FeeBumpTxIn::new(
            OutPoint {
                txid: feebump_tx.0.txid(),
                vout: 0,
            },
            feebump_txo.clone(),
        );
        let mut unemergency_tx = UnvaultEmergencyTransaction::new(
            rev_unvault_txin.clone(),
            Some(feebump_txin),
            emergency_address,
            0,
        );
        satisfy_transaction_input(
            &secp,
            &mut unemergency_tx,
            0,
            &unemergency_tx_sighash,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
        // We don't have satisfied the feebump input yet!
        // Note that we clone because Miniscript's finalize() will wipe the PSBT input..
        match unemergency_tx.clone().finalize(&secp) {
            Err(e) => assert!(
                e.to_string()
                    .contains("Missing pubkey for a pkh/wpkh at index 1"),
                "Got another error: {}",
                e
            ),
            Ok(_) => unreachable!(),
        }
        // Now actually satisfy it, libbitcoinconsensus should not yell
        let unemer_tx_sighash_feebump = unemergency_tx
            .signature_hash_feebump_input(1, &feebump_descriptor.script_code(), SigHashType::All)
            .expect("Input exists");
        satisfy_transaction_input(
            &secp,
            &mut unemergency_tx,
            1,
            &unemer_tx_sighash_feebump,
            &vec![feebump_xpriv],
            None,
            SigHashType::All,
        )?;
        unemergency_tx.finalize(&secp)?;

        // Now we can sign the unvault
        let unvault_tx_sighash = unvault_tx
            .signature_hash_internal_input(0, SigHashType::All)
            .expect("Input exists");
        satisfy_transaction_input(
            &secp,
            &mut unvault_tx,
            0,
            &unvault_tx_sighash,
            &stakeholders_priv,
            Some(child_number),
            SigHashType::All,
        )?;

        unvault_tx.finalize(&secp)?;

        // Create and sign a spend transaction
        let spend_unvault_txin = unvault_tx.spend_unvault_txin(&der_unvault_descriptor); // Off-by-one csv
        let dummy_txo = ExternalTxOut::default();
        let cpfp_value = SpendTransaction::cpfp_txout(
            vec![spend_unvault_txin.clone()],
            vec![SpendTxOut::Destination(dummy_txo.clone())],
            &der_cpfp_descriptor,
            0,
        )
        .txout()
        .value;
        let fees = 20_000;
        let spend_txo = ExternalTxOut::new(TxOut {
            // The CPFP output value won't be > 150k sats for our parameters
            value: spend_unvault_txin.txout().txout().value - cpfp_value - fees,
            ..TxOut::default()
        });

        // "This time for sure !"
        let spend_unvault_txin = unvault_tx.spend_unvault_txin(&der_unvault_descriptor); // Right csv
        let mut spend_tx = SpendTransaction::new(
            vec![spend_unvault_txin],
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &der_cpfp_descriptor,
            0,
            true,
        )
        .expect("Amounts ok");
        let spend_tx_sighash = spend_tx
            .signature_hash_internal_input(0, SigHashType::All)
            .expect("Input exists");
        satisfy_transaction_input(
            &secp,
            &mut spend_tx,
            0,
            &spend_tx_sighash,
            &managers_priv
                .iter()
                .chain(cosigners_priv.iter())
                .copied()
                .collect::<Vec<bip32::ExtendedPrivKey>>(),
            Some(child_number),
            SigHashType::All,
        )?;
        spend_tx.finalize(&secp)?;

        // The spend transaction can also batch multiple unvault txos
        let spend_unvault_txins = vec![
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "0ed7dc14fe8d1364b3185fa46e940cb8e858f8de32e63f88353a2bd66eb99e2a:0",
                )
                .unwrap(),
                UnvaultTxOut::new(deposit_value, &der_unvault_descriptor),
                csv,
            ),
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "23aacfca328942892bb007a86db0bf5337005f642b3c46aef50c23af03ec333a:1",
                )
                .unwrap(),
                UnvaultTxOut::new(deposit_value * 4, &der_unvault_descriptor),
                csv,
            ),
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "fccabf4077b7e44ba02378a97a84611b545c11a1ef2af16cbb6e1032aa059b1d:0",
                )
                .unwrap(),
                UnvaultTxOut::new(deposit_value / 2, &der_unvault_descriptor),
                csv,
            ),
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "71dc04303184d54e6cc2f92d843282df2854d6dd66f10081147b84aeed830ae1:0",
                )
                .unwrap(),
                UnvaultTxOut::new(deposit_value * 50, &der_unvault_descriptor),
                csv,
            ),
        ];
        let n_txins = spend_unvault_txins.len();
        let dummy_txo = ExternalTxOut::default();
        let cpfp_value = SpendTransaction::cpfp_txout(
            spend_unvault_txins.clone(),
            vec![SpendTxOut::Destination(dummy_txo.clone())],
            &der_cpfp_descriptor,
            0,
        )
        .txout()
        .value;
        let fees = 30_000;
        let spend_txo = ExternalTxOut::new(TxOut {
            value: spend_unvault_txins
                .iter()
                .map(|txin| txin.txout().txout().value)
                .sum::<u64>()
                - cpfp_value
                - fees,
            ..TxOut::default()
        });
        let mut spend_tx = SpendTransaction::new(
            spend_unvault_txins,
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &der_cpfp_descriptor,
            0,
            true,
        )
        .expect("Amounts Ok");
        assert_eq!(spend_tx.fees(), fees);
        for i in 0..n_txins {
            let spend_tx_sighash = spend_tx
                .signature_hash_internal_input(i, SigHashType::All)
                .expect("Input exists");
            satisfy_transaction_input(
                &secp,
                &mut spend_tx,
                i,
                &spend_tx_sighash,
                &managers_priv
                    .iter()
                    .chain(cosigners_priv.iter())
                    .copied()
                    .collect::<Vec<bip32::ExtendedPrivKey>>(),
                Some(child_number),
                SigHashType::All,
            )?
        }
        spend_tx.finalize(&secp)?;

        // Test that we can get the hexadecimal representation of each transaction without error
        unvault_tx.hex();
        spend_tx.hex();
        cancel_tx.hex();
        emergency_tx.hex();

        #[cfg(feature = "use-serde")]
        {
            macro_rules! roundtrip {
                ($tx:ident) => {
                    let serialized_tx = serde_json::to_string(&$tx).unwrap();
                    let deserialized_tx = serde_json::from_str(&serialized_tx).unwrap();
                    assert_eq!($tx, deserialized_tx);
                };
            }

            roundtrip!(emergency_tx);
            roundtrip!(unvault_tx);
            roundtrip!(unemergency_tx);
            roundtrip!(spend_tx);
        }

        Ok(())
    }

    // Small sanity checks, see fuzzing targets for more.
    #[cfg(feature = "use-serde")]
    #[test]
    fn test_deserialize_psbt() {
        let emergency_psbt_str = "\"cHNidP8BAIcCAAAAAuEAZNxAy8+vO2xoZFvsBYlgw6wk5hMFlx2QfdJAB5dwAAAAAAD9////RpNyUTczj4LUHy4abwuVEH/ha2LhNEkhCljpi+DXvV4AAAAAAP3///8B92ADAAAAAAAiACB0FMmRlU42BMGHgxBjusio4tqifT6ICZ4n3kLt+3y8aAAAAAAAAQErh5QDAAAAAAAiACB0FMmRlU42BMGHgxBjusio4tqifT6ICZ4n3kLt+3y8aCICAtWJr8yKNegqMu9EXe0itf+ZHUpXnhy3kfQeJhP2ofJvSDBFAiEAze1vfVVe1iXV5BZRn4g2bVAmmIoT8nBIzzwxY5yC7eICIEtOnT/7Fw8mS08BbWW19gsTYZzFEBLmJi16OY7DLUPsgSICAg8j1MWiUjZfCK95R07epNukSEsiq1dD/LUlYdW6UArSSDBFAiEArazAnifYyQiE520TFE+qVHrRhtQIhhkJVZ01Aw4OEvUCIEuqzr2McD3zGnEc/yiv1oT1HAuPj0SMIAbk+qgQbHGLgQEDBIEAAAABBUdSIQIPI9TFolI2XwiveUdO3qTbpEhLIqtXQ/y1JWHVulAK0iEC1YmvzIo16Coy70Rd7SK1/5kdSleeHLeR9B4mE/ah8m9SrgABAR+a3QAAAAAAABYAFB5/7V9SvO31sHrYLQ+kuyZaMDkXIgIC5AXAiBkRjiyCnRA7ERx5zxHpEf0/DmrWiF9CstSuJeFIMEUCIQCQ/tFT2iK7rAl57tiXidM7JJ+TVx1FXg4Vu+4EJp5bSwIgOnfEV+xO59P7DJvvEue7qSRDNTGpzRQwwsP5yokME9YBAQMEAQAAAAAA\"";
        let emergency_tx: EmergencyTransaction = serde_json::from_str(&emergency_psbt_str).unwrap();
        assert_eq!(emergency_tx.hex().as_str(), "0200000002e10064dc40cbcfaf3b6c68645bec058960c3ac24e61305971d907dd2400797700000000000fdffffff4693725137338f82d41f2e1a6f0b95107fe16b62e13449210a58e98be0d7bd5e0000000000fdffffff01f7600300000000002200207414c991954e3604c187831063bac8a8e2daa27d3e88099e27de42edfb7cbc6800000000");

        let unvault_psbt_str = "\"cHNidP8BAIkCAAAAAcNuW/2BGMjVscmagDIp0qcLczfNqcYsR0VmBlH0RKSxAAAAAAD9////AkANAwAAAAAAIgAg+aW89btq9yILwX2pSyXJVkCbXsMhUYUKiS9DK3TF42kwdQAAAAAAACIAIMd3+o0VPULHPxJ3dJNASnrGGZpKuuWXCQvPqH5VelwfAAAAAAABASuIlAMAAAAAACIAIE0NCW/hG4IJz3MGCXWOAxzUOoeCsAb8+wHCjZ8nbdjVIgID9cKEhz20F3M+WmbI6fJ/feB9/3pB7koww2bS7UXwtwNHMEQCIEKMsiuj3G7FYxYyHJ49SLNDiAN7raGfdit6a34S87vmAiAuTAGPx3oEo5cE4qa8M6+jmkfHOjS6HzIsBJTUaEFK5wEiAgKYBZ07lA0xglPqVmsqvbvk9Nr5c8vO4Qfrfg1aE05KjkcwRAIgNUEqQwg62+DsrRkEKGaxVPZJtsblXDf5+EaKTOC+XXUCICLe6EMJRW+gyeEdQ3xeJ8IzspVSPZ4Yr1mUmOLyDTzqAQEDBAEAAAABBUdSIQP1woSHPbQXcz5aZsjp8n994H3/ekHuSjDDZtLtRfC3AyECmAWdO5QNMYJT6lZrKr275PTa+XPLzuEH634NWhNOSo5SrgABAashA572FVyzkVmn2VFQgcflckhMyUlgiKS59dRKjkY/um3trFGHZHapFMF2tEWP+sH2PBsMi9ebGQJ+OCyDiKxrdqkUrOnriNTE8/ct3vDm5450tA6IzJ6IrGyTUodnUiED1gNSfO7c/ssUM6GsmpnnbFpjTo3QBd5ioVkPjYPYfU0hAzPCmTt3aK+Gv3oUQ00b5OB3or92V8aSLpnbXJICtHAgUq8DqYwAsmgAAQElIQOe9hVcs5FZp9lRUIHH5XJITMlJYIikufXUSo5GP7pt7axRhwA=\"";
        let unvault_tx: UnvaultTransaction = serde_json::from_str(&unvault_psbt_str).unwrap();
        assert_eq!(unvault_tx.hex().as_str(), "0200000001c36e5bfd8118c8d5b1c99a803229d2a70b7337cda9c62c4745660651f444a4b10000000000fdffffff02400d030000000000220020f9a5bcf5bb6af7220bc17da94b25c956409b5ec32151850a892f432b74c5e3693075000000000000220020c777fa8d153d42c73f12777493404a7ac6199a4abae597090bcfa87e557a5c1f00000000");

        let cancel_psbt_str = "\"cHNidP8BAIcCAAAAAkzK5VoK+JM1I4Xw3KiZP35JunqWaha/kxVH9Fc319rXAAAAAAD9////X9QhbL8SgePLKkLsEYjqhfvEGuCKCVA+gbLKqED1LCcAAAAAAP3///8B0soCAAAAAAAiACBa7dstF6Vns+rNRmKY7eGlFhEC2AAtFyTTeDgluwC2dQAAAAAAAQErQA0DAAAAAAAiACC+HKr/IXfz+quxmQ5qtpJCxZoxx+qrRk4C9POIjpNtcCICAgOXAVovp7XCt5x9D2Sm9/AUXznCaff+S/E6Jy70QLwBRzBEAiAy4dGtkOpTo4Wfpfy2rQPHl2r7XFHTuA2yph4+NDJwRAIgUCQVs1jd1CwvIYveS1EC5sNnDdQktHWkr6WyWnG+duGBIgIDCLuhnyMFaiARCK4sPM8o59gvmw7TyPWOfV9Ayqc7ZahIMEUCIQC2SmI3M+joZZEAg6yoo6blcfKKaMQ9qxcITsDRFyeOxwIgThKCj6Ff4osPuAUA1EIPLxVrAHpKSJGpFGdQGpFTzfOBAQMEgQAAAAEFqyECMBWn8Nqgn7qUY1l+vvScCE4qqbxVBdTolF9Tkv3HjY2sUYdkdqkUeWykpAk/X2ax7K78ROp7r1WtskWIrGt2qRRQDXd90K8a9quA2J9lNts/kbniiYisbJNSh2dSIQIl55eP2dgCboG44aNDNCJvHN9E1q0xh9OzkWkpDT4JiSECcWxkAv3PuRl+Sw+Apd5i41Ezo37D7OecM3xe5eLYZY9SrwNdhgCyaAABAR+a3QAAAAAAABYAFO+2Up6bJOYgAT5JTiN1eP0QVoSjIgIDuy9MjTR/VKR5dOisywUugQJfVeuaYxAc7Lsx+Tey1jJIMEUCIQC/jvo652Srj3gD3GHtn6IaGVcJe6vkae5Tpz6CIVjl6QIgRC7zW3y4ELeM7Sx6nPfe1vyyWSYWaUG1S7v9qKtQK/0BAQMEAQAAAAABAUdSIQIDlwFaL6e1wrecfQ9kpvfwFF85wmn3/kvxOicu9EC8ASEDCLuhnyMFaiARCK4sPM8o59gvmw7TyPWOfV9Ayqc7ZahSrgA=\"";
        let cancel_tx: CancelTransaction = serde_json::from_str(&cancel_psbt_str).unwrap();
        assert_eq!(cancel_tx.hex().as_str(), "02000000024ccae55a0af893352385f0dca8993f7e49ba7a966a16bf931547f45737d7dad70000000000fdffffff5fd4216cbf1281e3cb2a42ec1188ea85fbc41ae08a09503e81b2caa840f52c270000000000fdffffff01d2ca0200000000002200205aeddb2d17a567b3eacd466298ede1a5161102d8002d1724d3783825bb00b67500000000");

        let unemergency_psbt_str = "\"cHNidP8BAIcCAAAAAjyplGpzwkN/c/J75I4KXj7T0IxdhbgFvD5tU4Blnu7KAAAAAAD9////ur9klIwGPaAJacaRQjZpqT9Obs7lska/UMIYQNIH0rcAAAAAAP3///8B0soCAAAAAAAiACCTwim9CPURWR1tVH0w4Y2htmm1Ehh3lq2v1GXhrNUrJwAAAAAAAQErQA0DAAAAAAAiACAACUXLCIZBJ3kDiQattxqigOSInOlK95jxt6EALplTmiICA4OOG3CDuASrKTLzHkEXMImS4aRuzwYLCcTenQH86TLUSDBFAiEA2Sho2nPY66x309D84Bg1twwDOTsUXZ/VmU9MJD9Q4NwCIH1Xh/iloOuo88w9Sc5vDt8Fu385g74+kIwoTykFxbrzgSICAwXaX6NHGbjnVBZYyOIGlLGIRQuIrlN/9dzPz+wZ8hX/RzBEAiACe6bwR6lmcUqfFI/bWoda7q68jc2NNjwJXvG9myGicgIgakM2wQXYqWlEyxwIfyiBkdKT6mWAoPUVq5VFETknf/aBAQMEgQAAAAEFqyECvmXlD4O+L/PFOPumxXyqXd75CEdOPu9lF3gYHLFn4GKsUYdkdqkU7bwUkACg4kLrKTZ9JPFXAuVlvO2IrGt2qRRtrZkIOsEBwl/MbemKESkFo3OllIisbJNSh2dSIQPOgJoUmqKJHsneJ0rfZU3GJaor5YspkCEPTKVbu65vWiECdDni0vMnZykunRfyZWfjOlmD3iJMuptvRti4N89Ty65SrwOyigCyaAABAR+a3QAAAAAAABYAFDD9xz18wXMKz9j0B6pHKbLXMQEOIgICNL89JGq3AY8G+GX+dChQ4WnmeluAZNMgQVkxH/0MX4tIMEUCIQCDqaRzs/7gLCxV1o1qPOJT7xdjAW38SVMY4o2JXR3LkwIgIsGL9LR3nsTuzPfSEMTUyKnPZ+07Rr8GOTGuZ4YsYtYBAQMEAQAAAAAA\"";
        let unemergency_tx: UnvaultEmergencyTransaction =
            serde_json::from_str(&unemergency_psbt_str).unwrap();
        assert_eq!(unemergency_tx.hex().as_str(), "02000000023ca9946a73c2437f73f27be48e0a5e3ed3d08c5d85b805bc3e6d5380659eeeca0000000000fdffffffbabf64948c063da00969c691423669a93f4e6ecee5b246bf50c21840d207d2b70000000000fdffffff01d2ca02000000000022002093c229bd08f511591d6d547d30e18da1b669b512187796adafd465e1acd52b2700000000");

        let spend_psbt_str = "\"cHNidP8BAOICAAAABCqeuW7WKzo1iD/mMt74WOi4DJRupF8Ys2QTjf4U3NcOAAAAAABe0AAAOjPsA68jDPWuRjwrZF8AN1O/sG2oB7AriUKJMsrPqiMBAAAAAF7QAAAdmwWqMhBuu2zxKu+hEVxUG2GEeql4I6BL5Ld3QL/K/AAAAAAAXtAAAOEKg+2uhHsUgQDxZt3WVCjfgjKELfnCbE7VhDEwBNxxAAAAAABe0AAAAgBvAgAAAAAAIgAgKjuiJEE1EeX8hEfJEB1Hfi+V23ETrp/KCx74SqwSLGBc9sMAAAAAAAAAAAAAAAEBK4iUAwAAAAAAIgAgRAzbIqFTxU8vRmZJTINVkIFqQsv6nWgsBrqsPSo3yg4BCP2IAQUASDBFAiEAo2IX4SPeqXGdu8cEB13BkfCDk1N+kf8mMOrwx6uJZ3gCIHYEspD4EUjt+PM8D4T5qtE5GjUT56aH9yEmf8SCR63eAUcwRAIgVdpttzz0rxS/gpSTPcG3OIQcLWrTcSFc6vthcBrBTZQCIDYm952TZ644IEETblK7N434NrFql7ccFTM7+jUj+9unAUgwRQIhALKhtFWbyicZtKuqfBcjKfl7GY1e2i2UTSS2hMtCKRIyAiA410YD546ONeAq2+CPk86Q1dQHUIRj+OQl3dmKvo/aFwGrIQPazx7E2MqqusRekjfgnWmq3OG4lF3MR3b+c/ufTDH3pKxRh2R2qRRZT2zQxRaHYRlox31j9A8EIu4mroisa3apFH7IHjHORqjFOYgmE+5URE+rT+iiiKxsk1KHZ1IhAr+ZWb/U4iUT5Vu1kF7zoqKfn5JK2wDGJ/0dkrZ/+c+UIQL+mr8QPqouEYAyh3QmEVU4Dv9BaheeYbCkvpmryviNm1KvA17QALJoAAEBKyBSDgAAAAAAIgAgRAzbIqFTxU8vRmZJTINVkIFqQsv6nWgsBrqsPSo3yg4BCP2GAQUARzBEAiAZR0TO1PRje6KzUb0lYmMuk6DjnMCHcCUU/Ct/otpMCgIgcAgD7H5oGx6jG2RjcRkS3HC617v1C58+BjyUKowb/nIBRzBEAiAhYwZTODb8zAjwfNjt5wL37yg1OZQ9wQuTV2iS7YByFwIgGb008oD3RXgzE3exXLDzGE0wst24ft15oLxj2xeqcmsBRzBEAiA6JMEwOeGlq92NItxEA2tBW5akps9EkUX1vMiaSM8yrwIgUsaiU94sOOQf/5zxb0hpp44HU17FgGov8/mFy3mT++IBqyED2s8exNjKqrrEXpI34J1pqtzhuJRdzEd2/nP7n0wx96SsUYdkdqkUWU9s0MUWh2EZaMd9Y/QPBCLuJq6IrGt2qRR+yB4xzkaoxTmIJhPuVERPq0/oooisbJNSh2dSIQK/mVm/1OIlE+VbtZBe86Kin5+SStsAxif9HZK2f/nPlCEC/pq/ED6qLhGAMod0JhFVOA7/QWoXnmGwpL6Zq8r4jZtSrwNe0ACyaAABAStEygEAAAAAACIAIEQM2yKhU8VPL0ZmSUyDVZCBakLL+p1oLAa6rD0qN8oOAQj9iAEFAEgwRQIhAL6mDIPbQZc8Y51CzTUl7+grFUVr+6CpBPt3zLio4FTLAiBkmNSnd8VvlD84jrDx12Xug5XRwueBSG0N1PBwCtyPCQFHMEQCIFLryPMdlr0XLySRzYWw75tKofJAjhhXgc1XpVDXtPRjAiBp+eeNA5Zl1aU8E3UtFxnlZ5KMRlIZpkqn7lvIlXi0rQFIMEUCIQCym/dSaqtfrTb3fs1ig1KvwS0AwyoHR62R3WGq52fk0gIgI/DAQO6EyvZT1UHYtfGsZHLlIZkFYRLZnTpznle/qsUBqyED2s8exNjKqrrEXpI34J1pqtzhuJRdzEd2/nP7n0wx96SsUYdkdqkUWU9s0MUWh2EZaMd9Y/QPBCLuJq6IrGt2qRR+yB4xzkaoxTmIJhPuVERPq0/oooisbJNSh2dSIQK/mVm/1OIlE+VbtZBe86Kin5+SStsAxif9HZK2f/nPlCEC/pq/ED6qLhGAMod0JhFVOA7/QWoXnmGwpL6Zq8r4jZtSrwNe0ACyaAABASuQArMAAAAAACIAIEQM2yKhU8VPL0ZmSUyDVZCBakLL+p1oLAa6rD0qN8oOAQj9iQEFAEgwRQIhAK8fSyw0VbBElw6L9iyedbSz6HtbrHrzs+M6EB4+6+1yAiBMN3s3ZKff7Msvgq8yfrI9v0CK5IKEoacgb0PcBKCzlwFIMEUCIQDyIe5RXWOu8PJ1Rbc2Nn0NGuPORDO4gYaGWH3swEixzAIgU2/ft0cNzSjbgT0O/MKss2Sk0e7OevzclRBSWZP3SHQBSDBFAiEA+spp4ejHuWnwymZqNYaTtrrFC5wCw3ItwtJ6DMxmRWMCIAbOYDm/yuiijXSz1YTDdyO0Zpg6TAzLY1kd90GFhQpRAashA9rPHsTYyqq6xF6SN+Cdaarc4biUXcxHdv5z+59MMfekrFGHZHapFFlPbNDFFodhGWjHfWP0DwQi7iauiKxrdqkUfsgeMc5GqMU5iCYT7lRET6tP6KKIrGyTUodnUiECv5lZv9TiJRPlW7WQXvOiop+fkkrbAMYn/R2Stn/5z5QhAv6avxA+qi4RgDKHdCYRVTgO/0FqF55hsKS+mavK+I2bUq8DXtAAsmgAAQElIQPazx7E2MqqusRekjfgnWmq3OG4lF3MR3b+c/ufTDH3pKxRhwAA\"";
        let spend_tx: SpendTransaction = serde_json::from_str(&spend_psbt_str).unwrap();
        assert_eq!(spend_tx.hex().as_str(), "020000000001042a9eb96ed62b3a35883fe632def858e8b80c946ea45f18b364138dfe14dcd70e00000000005ed000003a33ec03af230cf5ae463c2b645f003753bfb06da807b02b89428932cacfaa2301000000005ed000001d9b05aa32106ebb6cf12aefa1115c541b61847aa97823a04be4b77740bfcafc00000000005ed00000e10a83edae847b148100f166ddd65428df8232842df9c26c4ed584313004dc7100000000005ed0000002006f0200000000002200202a3ba224413511e5fc8447c9101d477e2f95db7113ae9fca0b1ef84aac122c605cf6c30000000000000500483045022100a36217e123dea9719dbbc704075dc191f08393537e91ff2630eaf0c7ab89677802207604b290f81148edf8f33c0f84f9aad1391a3513e7a687f721267fc48247adde01473044022055da6db73cf4af14bf8294933dc1b738841c2d6ad371215ceafb61701ac14d9402203626f79d9367ae382041136e52bb378df836b16a97b71c15333bfa3523fbdba701483045022100b2a1b4559bca2719b4abaa7c172329f97b198d5eda2d944d24b684cb42291232022038d74603e78e8e35e02adbe08f93ce90d5d407508463f8e425ddd98abe8fda1701ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b26805004730440220194744ced4f4637ba2b351bd2562632e93a0e39cc087702514fc2b7fa2da4c0a0220700803ec7e681b1ea31b6463711912dc70bad7bbf50b9f3e063c942a8c1bfe72014730440220216306533836fccc08f07cd8ede702f7ef283539943dc10b93576892ed807217022019bd34f280f74578331377b15cb0f3184d30b2ddb87edd79a0bc63db17aa726b0147304402203a24c13039e1a5abdd8d22dc44036b415b96a4a6cf449145f5bcc89a48cf32af022052c6a253de2c38e41fff9cf16f4869a78e07535ec5806a2ff3f985cb7993fbe201ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b2680500483045022100bea60c83db41973c639d42cd3525efe82b15456bfba0a904fb77ccb8a8e054cb02206498d4a777c56f943f388eb0f1d765ee8395d1c2e781486d0dd4f0700adc8f0901473044022052ebc8f31d96bd172f2491cd85b0ef9b4aa1f2408e185781cd57a550d7b4f463022069f9e78d039665d5a53c13752d1719e567928c465219a64aa7ee5bc89578b4ad01483045022100b29bf7526aab5fad36f77ecd628352afc12d00c32a0747ad91dd61aae767e4d2022023f0c040ee84caf653d541d8b5f1ac6472e52199056112d99d3a739e57bfaac501ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b2680500483045022100af1f4b2c3455b044970e8bf62c9e75b4b3e87b5bac7af3b3e33a101e3eebed7202204c377b3764a7dfeccb2f82af327eb23dbf408ae48284a1a7206f43dc04a0b39701483045022100f221ee515d63aef0f27545b736367d0d1ae3ce4433b8818686587decc048b1cc0220536fdfb7470dcd28db813d0efcc2acb364a4d1eece7afcdc9510525993f7487401483045022100faca69e1e8c7b969f0ca666a358693b6bac50b9c02c3722dc2d27a0ccc664563022006ce6039bfcae8a28d74b3d584c37723b466983a4c0ccb63591df74185850a5101ab2103dacf1ec4d8caaabac45e9237e09d69aadce1b8945dcc4776fe73fb9f4c31f7a4ac51876476a914594f6cd0c51687611968c77d63f40f0422ee26ae88ac6b76a9147ec81e31ce46a8c539882613ee54444fab4fe8a288ac6c93528767522102bf9959bfd4e22513e55bb5905ef3a2a29f9f924adb00c627fd1d92b67ff9cf942102fe9abf103eaa2e1180328774261155380eff416a179e61b0a4be99abcaf88d9b52af035ed000b26800000000");
    }
}
