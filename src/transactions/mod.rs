//! Revault transactions
//!
//! Typesafe routines to create Revault-specific Bitcoin transactions.
//!
//! We use PSBTs as defined in [bip-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
//! for data structure as well as roles distribution.

use crate::{error::*, scripts::*, txins::*, txouts::*};
use miniscript::bitcoin::{
    consensus::encode::Encodable,
    hash_types,
    hashes::Hash,
    secp256k1,
    util::{bip143::SigHashCache, bip32::ChildNumber, psbt::PartiallySignedTransaction as Psbt},
    Address, Amount, Network, OutPoint, PublicKey as BitcoinPubKey, Script, SigHash, SigHashType,
    Transaction, Txid, Wtxid,
};

use std::fmt;

#[macro_use]
mod utils;

mod cancel;
mod emergency;
mod spend;
mod unvault;
mod unvaultemergency;

pub use cancel::CancelTransaction;
pub use emergency::EmergencyTransaction;
pub use spend::SpendTransaction;
pub use unvault::UnvaultTransaction;
pub use unvaultemergency::UnvaultEmergencyTransaction;

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
///
/// <https://github.com/bitcoin/bitcoin/blob/590e49ccf2af27c6c1f1e0eb8be3a4bf4d92ce8b/src/policy/policy.h#L23-L24>
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
    /// Get the inner PSBT
    fn psbt(&self) -> &Psbt;

    // FIXME: how can we not expose this? This in theory breaks our internal assumptions as the
    // caller could just put the inner PSBT in an insane state..
    /// Get the inner PSBT
    fn psbt_mut(&mut self) -> &mut Psbt;

    /// Move inner PSBT out
    fn into_psbt(self) -> Psbt;

    /// Get the sighash for an input of a Revault transaction. Will deduce the scriptCode from
    /// the previous scriptPubKey type, assuming either P2WSH or P2WPKH.
    ///
    /// Will error if the input is out of bounds or the PSBT input is insane (eg a P2WSH that
    /// does not contain a Witness Script (ie was already finalized)).
    fn signature_hash(
        &self,
        input_index: usize,
        sighash_type: SigHashType,
    ) -> Result<SigHash, InputSatisfactionError> {
        let mut cache = SigHashCache::new(self.tx());
        self.signature_hash_cached(input_index, sighash_type, &mut cache)
    }

    /// Cached version of [RevaultTransaction::signature_hash]
    fn signature_hash_cached(
        &self,
        input_index: usize,
        sighash_type: SigHashType,
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

        if prev_txo.script_pubkey.is_v0_p2wsh() {
            let witscript = psbtin
                .witness_script
                .as_ref()
                .ok_or(InputSatisfactionError::MissingWitnessScript)?;
            Ok(cache.signature_hash(input_index, &witscript, prev_txo.value, sighash_type))
        } else {
            assert!(
                prev_txo.script_pubkey.is_v0_p2wpkh(),
                "If not a P2WSH, it must be a feebump input."
            );
            let raw_pkh = &prev_txo.script_pubkey[2..];
            let pkh = hash_types::PubkeyHash::from_slice(raw_pkh).expect("Never fails");
            let witscript = Script::new_p2pkh(&pkh);
            Ok(cache.signature_hash(input_index, &witscript, prev_txo.value, sighash_type))
        }
    }

    /// Add a signature in order to eventually satisfy this input.
    ///
    /// Checks the signature according to the specified expected sighash type in the PSBT input.
    ///
    /// The BIP174 Signer role.
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

        let expected_sighash_type = psbtin
            .sighash_type
            .expect("We always set the SigHashType in the constructor.");
        let sighash = self.signature_hash(input_index, expected_sighash_type)?;
        let sighash = secp256k1::Message::from_slice(&sighash).expect("sighash is 32 a bytes hash");
        secp.verify(&sighash, &signature, &pubkey)
            .map_err(|_| InputSatisfactionError::InvalidSignature(signature, pubkey, sighash))?;

        let pubkey = BitcoinPubKey {
            compressed: true,
            key: pubkey,
        };
        let mut rawsig = signature.serialize_der().to_vec();
        rawsig.push(expected_sighash_type.as_u32() as u8);

        let psbtin = self
            .psbt_mut()
            .inputs
            .get_mut(input_index)
            .expect("Checked at the beginning.");
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

    fn fees(&self) -> u64 {
        let mut value_in: u64 = 0;
        for i in self.psbt().inputs.iter() {
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
        for o in self.psbt().global.unsigned_tx.output.iter() {
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

/// The fee-bumping transaction, we don't create nor sign it.
#[derive(Debug, Clone, PartialEq)]
pub struct FeeBumpTransaction(pub Transaction);

/// Get the chain of pre-signed transaction out of a deposit available for a manager.
/// No feebump input.
#[allow(clippy::too_many_arguments)]
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
        DepositTxOut::new(deposit_amount, &der_deposit_descriptor),
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
#[allow(clippy::too_many_arguments)]
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
        DepositTxOut::new(deposit_amount, &der_deposit_descriptor),
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
#[allow(clippy::too_many_arguments)]
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

            let txin = DepositTxIn::new(outpoint, DepositTxOut::new(amount, &der_deposit_desc));
            if deriv_index > max_deriv_index {
                max_deriv_index = deriv_index;
            }

            UnvaultTransaction::new(txin, &der_unvault_desc, &der_cpfp_desc, lock_time)
                .map(|unvault_tx| unvault_tx.spend_unvault_txin(&der_unvault_desc))
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
        let feebump_prevout = OutPoint::from_str(
            "4bb4545bb4bc8853cb03e42984d677fbe880c81e7d95609360eed0d8f45b52f8:0",
        )
        .unwrap();
        let feebump_value = 56730;
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
                feebump_prevout,
                feebump_value,
                unvaults_spent.clone(),
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
            300_000,
            feebump_prevout,
            feebump_value,
            unvaults_spent.clone(),
            &secp,
        )
        .expect_err("Unclean CSV");

        // Absolute minimum
        derive_transactions(
            2,
            1,
            csv,
            deposit_prevout,
            234_632,
            feebump_prevout,
            feebump_value,
            unvaults_spent.clone(),
            &secp,
        )
        .expect(&format!(
            "Tx chain with 2 stakeholders, 1 manager, {} csv, 235_250 deposit",
            csv
        ));
        // 1 BTC
        derive_transactions(
            8,
            3,
            csv,
            deposit_prevout,
            COIN_VALUE,
            feebump_prevout,
            feebump_value,
            unvaults_spent.clone(),
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
            feebump_prevout,
            feebump_value,
            unvaults_spent.clone(),
            &secp,
        )
        .expect(&format!(
            "Tx chain with 8 stakeholders, 3 managers, {} csv, 100_000_000_000_000 deposit",
            csv
        ));
        // 100 BTC
        derive_transactions(
            38,
            5,
            csv,
            deposit_prevout,
            100 * COIN_VALUE,
            feebump_prevout,
            feebump_value,
            unvaults_spent,
            &secp,
        )
        .expect(&format!(
            "Tx chain with 38 stakeholders, 5 manager, {} csv, 100_000_000_000 deposit",
            csv
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

        let emergency_psbt_str = "\"cHNidP8BAIcCAAAAArlxjSMtT1NW43OtU7paIqVl/6bzTw5Q5xX7lsGErjsMAAAAAAD9////aNrJbTchwjZaRiz9bZbIQxRo/wRp5LQANqA7qTHWtzsAAAAAAP3///8BGHb1BQAAAAAiACAA3UtE19HiWwGiB6ERj47s1dIBZwo69vjfXEQw1jdANgAAAAAAAQErAOH1BQAAAAAiACAA3UtE19HiWwGiB6ERj47s1dIBZwo69vjfXEQw1jdANgEDBIEAAAABBf0TAVghAslTGncWjnHdqiPxR0bCa47bbZ9IfacoUvOtMfezbzavIQJOoGnPoDCo/yIaRQyi0WbNhOBwjW9+KuyS0tXzNDOXaiEDhIEpuvcgOIYN3wvBFQs0Tfma6tvKlb94W80dUAzrvgMhAjJCk6/xHPV/zcdKEmqkAAVQmuXAyVVa4jX1PG+WIYgPIQNRzJs4CMgBDWWmmweCLf8OqoLNncEQszFWZ25aqYOEcSEDtXG6kmkdzbsLFIxb2x0iFLVokBAyaTipwn5HdpU34/8hAtiB7MFlv5uXBDBXui9tTgu6qsa2NBla4DY1G5GyuuB3IQPd8cUxIS+8niMSWK/5BXfBtCdZsPMHc1NpAvx80ZdjQFiuIgYCMkKTr/Ec9X/Nx0oSaqQABVCa5cDJVVriNfU8b5YhiA8IQohVzwoAAAAiBgJOoGnPoDCo/yIaRQyi0WbNhOBwjW9+KuyS0tXzNDOXagiO14bnCgAAACIGAslTGncWjnHdqiPxR0bCa47bbZ9IfacoUvOtMfezbzavCOEWDZEKAAAAIgYC2IHswWW/m5cEMFe6L21OC7qqxrY0GVrgNjUbkbK64HcIADRz8AoAAAAiBgNRzJs4CMgBDWWmmweCLf8OqoLNncEQszFWZ25aqYOEcQi93C9kCgAAACIGA4SBKbr3IDiGDd8LwRULNE35murbypW/eFvNHVAM674DCBdIsDYKAAAAIgYDtXG6kmkdzbsLFIxb2x0iFLVokBAyaTipwn5HdpU34/8IonEPuQoAAAAiBgPd8cUxIS+8niMSWK/5BXfBtCdZsPMHc1NpAvx80ZdjQAinqwY/CgAAAAABAR+a3QAAAAAAABYAFOq4VB+mNQOpoT6VOJRqxIa20L7LAQMEAQAAAAAA\"";
        let emergency_tx: EmergencyTransaction = serde_json::from_str(&emergency_psbt_str).unwrap();
        assert_eq!(serialize_hex(emergency_tx.tx()), "0200000002b9718d232d4f5356e373ad53ba5a22a565ffa6f34f0e50e715fb96c184ae3b0c0000000000fdffffff68dac96d3721c2365a462cfd6d96c8431468ff0469e4b40036a03ba931d6b73b0000000000fdffffff011876f5050000000022002000dd4b44d7d1e25b01a207a1118f8eecd5d201670a3af6f8df5c4430d637403600000000");

        let unvault_psbt_str = "\"cHNidP8BAIkCAAAAAV+HumeWIAtm1c9hvTgUme25aogn3EvF1+vV7KYKKKdYAAAAAAD9////AkANAwAAAAAAIgAgXA0s+qynDjinXOmpJ/Qhuj87xEB7YcLEVdz7OX5B+l8wdQAAAAAAACIAIKj/nBsC9abIRvrVxbaHRVSZNtMZjsOSosgybAbmDAtwAAAAAAABASuIlAMAAAAAACIAIKI1Ly2kCXvsF5kWmgyAGmH2th23XwgbIDHRo7sHndheAQMEAQAAAAEFR1IhAtk/sjHYB5gv7nUSr0k25UlmeCn+7ztrilD5aKBYhOZ/IQI+TfqYOB5AvGLZO2C3OWNepPtB2MXltlovJy9aNEUezFKuIgYCPk36mDgeQLxi2TtgtzljXqT7QdjF5bZaLycvWjRFHswIeMYQoQoAAAAiBgLZP7Ix2AeYL+51Eq9JNuVJZngp/u87a4pQ+WigWITmfwgbQV1zCgAAAAAAAA==\"";
        let unvault_tx: UnvaultTransaction = serde_json::from_str(&unvault_psbt_str).unwrap();
        assert_eq!(serialize_hex(unvault_tx.tx()), "02000000015f87ba6796200b66d5cf61bd381499edb96a8827dc4bc5d7ebd5eca60a28a7580000000000fdffffff02400d0300000000002200205c0d2cfaaca70e38a75ce9a927f421ba3f3bc4407b61c2c455dcfb397e41fa5f3075000000000000220020a8ff9c1b02f5a6c846fad5c5b68745549936d3198ec392a2c8326c06e60c0b7000000000");

        let cancel_psbt_str = "\"cHNidP8BAIcCAAAAAveVYT6dSrDTzQekeDseTQmpQChdIx9Fm/7yvPBvdu7HAAAAAAD9////4Mnw2eEzRAQN9WGGOBC1JjSnsKwwMSWyy5W8aSKNSi0AAAAAAP3///8B0soCAAAAAAAiACCiNS8tpAl77BeZFpoMgBph9rYdt18IGyAx0aO7B53YXgAAAAAAAQErQA0DAAAAAAAiACBcDSz6rKcOOKdc6akn9CG6PzvEQHthwsRV3Ps5fkH6XwEDBIEAAAABBashAzdYEJAzGF/LD6dywOpGk2BGFzVLcnkTZ5mTKtqZ//JirFGHZHapFPw384BoV7hrB0f9JGslZsJ1uyCsiKxrdqkUzzp61qJKQsBvVgSS98GIY+FvRdmIrGyTUodnUiEC8j/Vvs0fXs+g2kudjYEthMFAUzsMlF4Sx6XButeSclohAhiZCgN97zL8xRfmhrw3aDYZ48dco/n6iUEGNceCxC4XUq8DtYQAsmgiBgIYmQoDfe8y/MUX5oa8N2g2GePHXKP5+olBBjXHgsQuFwjDH9MoCgAAACIGAj5N+pg4HkC8Ytk7YLc5Y16k+0HYxeW2Wi8nL1o0RR7MCHjGEKEKAAAAIgYC2T+yMdgHmC/udRKvSTblSWZ4Kf7vO2uKUPlooFiE5n8IG0FdcwoAAAAiBgLyP9W+zR9ez6DaS52NgS2EwUBTOwyUXhLHpcG615JyWgjUBchUCgAAACIGAzdYEJAzGF/LD6dywOpGk2BGFzVLcnkTZ5mTKtqZ//JiCNB4cCcKAAAAAAEBH5rdAAAAAAAAFgAUn+xCi99KzUC3VoIqlu43HKa3qtYBAwQBAAAAAAA=\"";
        let cancel_tx: CancelTransaction = serde_json::from_str(&cancel_psbt_str).unwrap();
        assert_eq!(serialize_hex(cancel_tx.tx()), "0200000002f795613e9d4ab0d3cd07a4783b1e4d09a940285d231f459bfef2bcf06f76eec70000000000fdffffffe0c9f0d9e13344040df561863810b52634a7b0ac303125b2cb95bc69228d4a2d0000000000fdffffff01d2ca020000000000220020a2352f2da4097bec1799169a0c801a61f6b61db75f081b2031d1a3bb079dd85e00000000");

        let unemergency_psbt_str = "\"cHNidP8BAIcCAAAAAveVYT6dSrDTzQekeDseTQmpQChdIx9Fm/7yvPBvdu7HAAAAAAD9////4Mnw2eEzRAQN9WGGOBC1JjSnsKwwMSWyy5W8aSKNSi0AAAAAAP3///8B0soCAAAAAAAiACCiNS8tpAl77BeZFpoMgBph9rYdt18IGyAx0aO7B53YXgAAAAAAAQErQA0DAAAAAAAiACBcDSz6rKcOOKdc6akn9CG6PzvEQHthwsRV3Ps5fkH6XyICAj5N+pg4HkC8Ytk7YLc5Y16k+0HYxeW2Wi8nL1o0RR7MRzBEAiA/lmAObA+fV+HuMqDB5NT4rQ6z++xj6QpidJw5h7AJWAIgb4pmu9ufwM8Ou8lDCxszPw8XbTzM7ZbqEh5MazBIk5iBIgIC2T+yMdgHmC/udRKvSTblSWZ4Kf7vO2uKUPlooFiE5n9HMEQCIFX1NO7S1UsxOUiUFKD8+vbWmql6E4gd240MLs0Ht7A/AiAXinxaCoQ36FokIQbSPCaYI6OJDPsTM3YfemzoITvKHYEBAwSBAAAAAQWrIQM3WBCQMxhfyw+ncsDqRpNgRhc1S3J5E2eZkyramf/yYqxRh2R2qRT8N/OAaFe4awdH/SRrJWbCdbsgrIisa3apFM86etaiSkLAb1YEkvfBiGPhb0XZiKxsk1KHZ1IhAvI/1b7NH17PoNpLnY2BLYTBQFM7DJReEselwbrXknJaIQIYmQoDfe8y/MUX5oa8N2g2GePHXKP5+olBBjXHgsQuF1KvA7WEALJoIgYCGJkKA33vMvzFF+aGvDdoNhnjx1yj+fqJQQY1x4LELhcIwx/TKAoAAAAiBgI+TfqYOB5AvGLZO2C3OWNepPtB2MXltlovJy9aNEUezAh4xhChCgAAACIGAtk/sjHYB5gv7nUSr0k25UlmeCn+7ztrilD5aKBYhOZ/CBtBXXMKAAAAIgYC8j/Vvs0fXs+g2kudjYEthMFAUzsMlF4Sx6XButeScloI1AXIVAoAAAAiBgM3WBCQMxhfyw+ncsDqRpNgRhc1S3J5E2eZkyramf/yYgjQeHAnCgAAAAABAR+a3QAAAAAAABYAFJ/sQovfSs1At1aCKpbuNxymt6rWAQMEAQAAAAAA\"";
        let unemergency_tx: UnvaultEmergencyTransaction =
            serde_json::from_str(&unemergency_psbt_str).unwrap();
        assert_eq!(serialize_hex(unemergency_tx.tx()), "0200000002f795613e9d4ab0d3cd07a4783b1e4d09a940285d231f459bfef2bcf06f76eec70000000000fdffffffe0c9f0d9e13344040df561863810b52634a7b0ac303125b2cb95bc69228d4a2d0000000000fdffffff01d2ca020000000000220020a2352f2da4097bec1799169a0c801a61f6b61db75f081b2031d1a3bb079dd85e00000000");

        let spend_psbt_str = "\"cHNidP8BAOICAAAABCqeuW7WKzo1iD/mMt74WOi4DJRupF8Ys2QTjf4U3NcOAAAAAACgXwAAOjPsA68jDPWuRjwrZF8AN1O/sG2oB7AriUKJMsrPqiMBAAAAAKBfAAAdmwWqMhBuu2zxKu+hEVxUG2GEeql4I6BL5Ld3QL/K/AAAAAAAoF8AAOEKg+2uhHsUgQDxZt3WVCjfgjKELfnCbE7VhDEwBNxxAAAAAACgXwAAAoCbAAAAAAAAIgAgoQ7ROWxcN1XKPMUv51tXF2/PldG2/JFFK0l3pgCWlG7MosUAAAAAAAAAAAAAAAEBK4iUAwAAAAAAIgAgst7dESnds1s5jcXlQCSdCWnyt4zd96x6GbRKK4l4+egBAwQBAAAAAQWqIQMJ6Edoha1yM+zXgCEUz+TVnQXbKUKOKrdZUyxBIDC1s6xRh2R2qRTMeOF197paPoeh1cacfy9zi6E14oisa3apFLlIa5g6xRiNwXq6uJpRwM76Sv+IiKxsk1KHZ1IhAxNPjmgZyLu9Nq64cV+7QFUDAgdYtSE8ODhkt1TvdrP7IQPk3LhOsjuQcbwhTKJbtL8eXm+b4lkLnYAv4pp86edwK1KvAqBfsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAACIGAwnoR2iFrXIz7NeAIRTP5NWdBdspQo4qt1lTLEEgMLWzCCj7bQkKAAAAIgYDE0+OaBnIu702rrhxX7tAVQMCB1i1ITw4OGS3VO92s/sItasINQoAAAAiBgPMB3iEzsaSHYn4NKCSGTPRiR9oA65gwHIv2pGRCEiVrAjIj/QCCgAAACIGA+TcuE6yO5BxvCFMolu0vx5eb5viWQudgC/imnzp53ArCLsV/AsKAAAAAAEBKyBSDgAAAAAAIgAgst7dESnds1s5jcXlQCSdCWnyt4zd96x6GbRKK4l4+egBAwQBAAAAAQWqIQMJ6Edoha1yM+zXgCEUz+TVnQXbKUKOKrdZUyxBIDC1s6xRh2R2qRTMeOF197paPoeh1cacfy9zi6E14oisa3apFLlIa5g6xRiNwXq6uJpRwM76Sv+IiKxsk1KHZ1IhAxNPjmgZyLu9Nq64cV+7QFUDAgdYtSE8ODhkt1TvdrP7IQPk3LhOsjuQcbwhTKJbtL8eXm+b4lkLnYAv4pp86edwK1KvAqBfsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAACIGAwnoR2iFrXIz7NeAIRTP5NWdBdspQo4qt1lTLEEgMLWzCCj7bQkKAAAAIgYDE0+OaBnIu702rrhxX7tAVQMCB1i1ITw4OGS3VO92s/sItasINQoAAAAiBgPMB3iEzsaSHYn4NKCSGTPRiR9oA65gwHIv2pGRCEiVrAjIj/QCCgAAACIGA+TcuE6yO5BxvCFMolu0vx5eb5viWQudgC/imnzp53ArCLsV/AsKAAAAAAEBK0TKAQAAAAAAIgAgst7dESnds1s5jcXlQCSdCWnyt4zd96x6GbRKK4l4+egBAwQBAAAAAQWqIQMJ6Edoha1yM+zXgCEUz+TVnQXbKUKOKrdZUyxBIDC1s6xRh2R2qRTMeOF197paPoeh1cacfy9zi6E14oisa3apFLlIa5g6xRiNwXq6uJpRwM76Sv+IiKxsk1KHZ1IhAxNPjmgZyLu9Nq64cV+7QFUDAgdYtSE8ODhkt1TvdrP7IQPk3LhOsjuQcbwhTKJbtL8eXm+b4lkLnYAv4pp86edwK1KvAqBfsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAACIGAwnoR2iFrXIz7NeAIRTP5NWdBdspQo4qt1lTLEEgMLWzCCj7bQkKAAAAIgYDE0+OaBnIu702rrhxX7tAVQMCB1i1ITw4OGS3VO92s/sItasINQoAAAAiBgPMB3iEzsaSHYn4NKCSGTPRiR9oA65gwHIv2pGRCEiVrAjIj/QCCgAAACIGA+TcuE6yO5BxvCFMolu0vx5eb5viWQudgC/imnzp53ArCLsV/AsKAAAAAAEBK5ACswAAAAAAIgAgst7dESnds1s5jcXlQCSdCWnyt4zd96x6GbRKK4l4+egBAwQBAAAAAQWqIQMJ6Edoha1yM+zXgCEUz+TVnQXbKUKOKrdZUyxBIDC1s6xRh2R2qRTMeOF197paPoeh1cacfy9zi6E14oisa3apFLlIa5g6xRiNwXq6uJpRwM76Sv+IiKxsk1KHZ1IhAxNPjmgZyLu9Nq64cV+7QFUDAgdYtSE8ODhkt1TvdrP7IQPk3LhOsjuQcbwhTKJbtL8eXm+b4lkLnYAv4pp86edwK1KvAqBfsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAACIGAwnoR2iFrXIz7NeAIRTP5NWdBdspQo4qt1lTLEEgMLWzCCj7bQkKAAAAIgYDE0+OaBnIu702rrhxX7tAVQMCB1i1ITw4OGS3VO92s/sItasINQoAAAAiBgPMB3iEzsaSHYn4NKCSGTPRiR9oA65gwHIv2pGRCEiVrAjIj/QCCgAAACIGA+TcuE6yO5BxvCFMolu0vx5eb5viWQudgC/imnzp53ArCLsV/AsKAAAAAAAA\"";
        let spend_tx: SpendTransaction = serde_json::from_str(&spend_psbt_str).unwrap();
        assert_eq!(serialize_hex(&spend_tx.into_tx()), "02000000042a9eb96ed62b3a35883fe632def858e8b80c946ea45f18b364138dfe14dcd70e0000000000a05f00003a33ec03af230cf5ae463c2b645f003753bfb06da807b02b89428932cacfaa230100000000a05f00001d9b05aa32106ebb6cf12aefa1115c541b61847aa97823a04be4b77740bfcafc0000000000a05f0000e10a83edae847b148100f166ddd65428df8232842df9c26c4ed584313004dc710000000000a05f000002809b000000000000220020a10ed1396c5c3755ca3cc52fe75b57176fcf95d1b6fc91452b4977a60096946ecca2c500000000000000000000");
    }
}
