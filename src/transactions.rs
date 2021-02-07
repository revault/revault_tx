//! Revault transactions
//!
//! Typesafe routines to create Revault-specific Bitcoin transactions.
//!
//! We use PSBTs as defined in [bip-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
//! for data structure as well as roles distribution.

use crate::{
    scripts::{CpfpDescriptor, EmergencyAddress, UnvaultDescriptor, VaultDescriptor},
    txins::*,
    txouts::*,
    Error,
};

use miniscript::{
    bitcoin::{
        consensus::encode::{Decodable, Encodable},
        secp256k1,
        util::{
            bip143::SigHashCache,
            psbt::{
                Global as PsbtGlobal, Input as PsbtIn, Output as PsbtOut,
                PartiallySignedTransaction as Psbt,
            },
        },
        Address, Network, OutPoint, PublicKey as BitcoinPubKey, Script, SigHash, SigHashType,
        Transaction,
    },
    BitcoinSig, MiniscriptKey, ToPublicKey,
};

#[cfg(feature = "use-serde")]
use {
    serde::de::{self, Deserialize, Deserializer},
    serde::ser::{self, Serialize, Serializer},
};

use std::{collections::BTreeMap, convert::TryInto, fmt};

/// The value of the CPFP output in the Unvault transaction.
/// See https://github.com/re-vault/practical-revault/blob/master/transactions.md#unvault_tx
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

/// A Revault transaction.
///
/// Wraps a rust-bitcoin PSBT and defines some BIP174 roles as methods.
/// Namely:
/// - Creator and updater
/// - Signer
/// - Finalizer
/// - Extractor and serializer
pub trait RevaultTransaction: fmt::Debug + Clone + PartialEq {
    /// Get the inner transaction
    fn inner_tx(&self) -> &Psbt;

    /// Get the inner transaction
    fn inner_tx_mut(&mut self) -> &mut Psbt;

    /// Get the sighash for a specified input, provided the previous txout's scriptCode.
    fn signature_hash(
        &self,
        input_index: usize,
        // In theory, we could deduce this from the PSBT input. In practice it's hacky af and the
        // caller likely has the descriptor of this utxo already.
        script_code: &Script,
        sighash_type: SigHashType,
    ) -> Result<SigHash, Error> {
        let psbt = self.inner_tx();
        // TODO: maybe cache the cache at some point (for huge spend txs)
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_txo = psbt
            .inputs
            .get(input_index)
            .and_then(|psbtin| psbtin.witness_utxo.as_ref())
            .ok_or_else(|| {
                Error::InputSatisfaction(format!(
                    "Input index {} is out of bonds or psbt input has no witness utxo",
                    input_index
                ))
            })?;

        Ok(cache.signature_hash(input_index, &script_code, prev_txo.value, sighash_type))
    }

    // FIXME: parsing time checks! This function may (for now) panic when applied to an insane
    // parsed PSBT
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
    ) -> Result<Option<Vec<u8>>, Error> {
        let psbtin = match self.inner_tx_mut().inputs.get_mut(input_index) {
            Some(i) => i,
            None => {
                return Err(Error::InputSatisfaction(format!(
                    "Input out of bonds of PSBT inputs: {:?}",
                    self.inner_tx().inputs
                )))
            }
        };
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
            return Err(Error::InputSatisfaction(format!(
                "Unexpected sighash type for psbtin: '{:?}'",
                psbtin
            )));
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
        // We could operate on a clone for state consistency in case of error. However we never
        // leave the PSBT in an inconsistent state: worst case the final_script_witness will be set
        // and libbitcoinconsensus verification will fail. In this case it'll just get overidden at
        // the next call to finalize and nothing depends on it.
        let mut psbt = self.inner_tx_mut();

        // We only create transactions with witness_utxo, and spend P2WPKH or P2WSH outputs.
        debug_assert!(psbt
            .inputs
            .iter()
            .filter(|input| {
                let utxo = input
                    .witness_utxo
                    .as_ref()
                    .expect("PSBT input without witness_utxo");
                !(utxo.script_pubkey.is_v0_p2wpkh() || utxo.script_pubkey.is_v0_p2wsh())
            })
            .next()
            .is_none());

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

    /// Verify an input of the transaction against libbitcoinconsensus out of the information
    /// contained in the PSBT input.
    fn verify_input(&self, input_index: usize) -> Result<(), Error> {
        let (prev_scriptpubkey, prev_value) = self
            .inner_tx()
            .inputs
            .get(input_index)
            .and_then(|psbtin| {
                psbtin
                    .witness_utxo
                    .as_ref()
                    .map(|utxo| (utxo.script_pubkey.as_bytes(), utxo.value))
            })
            .ok_or_else(|| {
                Error::TransactionVerification(format!(
                    "No psbt input or no previous witness txo for psbt input at index '{}'",
                    input_index
                ))
            })?;
        let serialized_tx = self.as_bitcoin_serialized().map_err(|e| {
            Error::TransactionVerification(format!("Could not serialize transaction: '{}", e))
        })?;

        bitcoinconsensus::verify(
            prev_scriptpubkey,
            prev_value,
            serialized_tx.as_slice(),
            input_index,
        )
        .map_err(|e| Error::TransactionVerification(format!("Libbitcoinconsensus error: {:?}", e)))
    }

    // FIXME: should probably be into_bitcoin_serialized and not clone()
    /// Get the network-serialized (inner) transaction. You likely want to call
    /// [RevaultTransaction.finalize] before serializing the transaction.
    ///
    /// The BIP174 Transaction Extractor (without any check, which are done in
    /// [RevaultTransaction.finalize]).
    fn as_bitcoin_serialized(&self) -> Result<Vec<u8>, Error> {
        let mut buff = Vec::<u8>::new();
        self.inner_tx()
            .clone()
            .extract_tx()
            .consensus_encode(&mut buff)?;
        Ok(buff)
    }

    /// Get the BIP174-serialized (inner) transaction.
    fn as_psbt_serialized(&self) -> Result<Vec<u8>, Error> {
        let mut buff = Vec::<u8>::new();
        self.inner_tx().consensus_encode(&mut buff)?;
        Ok(buff)
    }

    /// Create a RevaultTransaction from a BIP174-serialized transaction.
    fn from_psbt_serialized(raw_psbt: &[u8]) -> Result<Self, Error>;

    /// Get the BIP174-serialized (inner) transaction encoded in base64.
    fn as_psbt_string(&self) -> Result<String, Error> {
        self.as_psbt_serialized().map(base64::encode)
    }

    /// Create a RevaultTransaction from a base64-encoded BIP174-serialized transaction.
    fn from_psbt_str(psbt_str: &str) -> Result<Self, Error> {
        Self::from_psbt_serialized(&base64::decode(&psbt_str)?)
    }

    /// Get the hexadecimal representation of the transaction as used by the bitcoind API.
    fn hex(&self) -> Result<String, Error> {
        let buff = self.as_bitcoin_serialized()?;
        let mut as_hex = String::new();

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
        pub struct $transaction_name(Psbt);

        impl RevaultTransaction for $transaction_name {
            fn inner_tx(&self) -> &Psbt {
                &self.0
            }

            fn inner_tx_mut(&mut self) -> &mut Psbt {
                &mut self.0
            }

            // TODO: move this to each transaction and perform actual checks..
            fn from_psbt_serialized(raw_psbt: &[u8]) -> Result<Self, Error> {
                Ok(Decodable::consensus_decode(raw_psbt).map(|psbt| $transaction_name(psbt))?)
            }
        }

        #[cfg(feature = "use-serde")]
        impl Serialize for $transaction_name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&self.as_psbt_string().map_err(ser::Error::custom)?)
                } else {
                    serializer
                        .serialize_bytes(&self.as_psbt_serialized().map_err(ser::Error::custom)?)
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
                    version: 2,
                    lock_time: $lock_time,
                    input: vec![$(
                        $revault_txin.unsigned_txin(),
                    )*],
                    output: vec![$(
                        $txout.clone().into_txout(),
                    )*],
                },
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

impl_revault_transaction!(
    UnvaultTransaction,
    doc = "The unvaulting transaction, spending a vault and being eventually spent by a spend transaction (if not revaulted)."
);
impl UnvaultTransaction {
    /// An unvault transaction always spends one vault output and contains one CPFP output in
    /// addition to the unvault one.
    /// It's always created using a fixed feerate and the CPFP output value is fixed as well.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        vault_input: VaultTxIn,
        unvault_descriptor: &UnvaultDescriptor<Pk>,
        cpfp_descriptor: &CpfpDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
        lock_time: u32,
    ) -> Result<UnvaultTransaction, Error> {
        // First, create a dummy transaction to get its weight without Witness
        let dummy_unvault_txout = UnvaultTxOut::new(u64::MAX, unvault_descriptor, to_pk_ctx);
        let dummy_cpfp_txout = CpfpTxOut::new(u64::MAX, cpfp_descriptor, to_pk_ctx);
        let dummy_tx = create_tx!(
            [(vault_input.clone(), SigHashType::All)],
            [dummy_unvault_txout, dummy_cpfp_txout],
            lock_time,
        )
        .global
        .unsigned_tx;

        // The weight of the transaction once signed will be the size of the witness-stripped
        // transaction plus the size of the single input's witness.
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(vault_input.max_sat_weight())
            .expect("Properly-computed weights cannot overflow");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = UNVAULT_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Properly-computed weights cannot overflow");
        // Nobody wants to pay 3k€ fees if we had a bug.
        if fees > INSANE_FEES {
            return Err(Error::TransactionCreation(format!(
                "Insane fee computation: {}sats > {}sats",
                fees, INSANE_FEES
            )));
        }

        // The unvault output value is then equal to the deposit value minus the fees and the CPFP.
        let deposit_value = vault_input.txout().txout().value;
        if fees + UNVAULT_CPFP_VALUE + DUST_LIMIT > deposit_value {
            return Err(Error::TransactionCreation(format!(
                "Deposit is {} sats but we need at least {} (fees) + {} (cpfp) + {} (dust limit)",
                deposit_value, fees, UNVAULT_CPFP_VALUE, DUST_LIMIT
            )));
        }
        let unvault_value = deposit_value - fees - UNVAULT_CPFP_VALUE; // Arithmetic checked above

        let unvault_txout = UnvaultTxOut::new(unvault_value, unvault_descriptor, to_pk_ctx);
        let cpfp_txout = CpfpTxOut::new(UNVAULT_CPFP_VALUE, cpfp_descriptor, to_pk_ctx);
        Ok(UnvaultTransaction(create_tx!(
            [(vault_input, SigHashType::All)],
            [unvault_txout, cpfp_txout],
            lock_time,
        )))
    }

    /// Get the Unvault txo to be referenced in a spending transaction
    pub fn unvault_txin<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        &self,
        unvault_descriptor: &UnvaultDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
        csv: u32,
    ) -> Option<UnvaultTxIn> {
        let spk = unvault_descriptor.0.script_pubkey(to_pk_ctx);
        let index = self
            .inner_tx()
            .global
            .unsigned_tx
            .output
            .iter()
            .position(|txo| txo.script_pubkey == spk)?;

        // If we don't have both at this point, there is a consequent logic error..
        debug_assert!(
            self.inner_tx()
                .global
                .unsigned_tx
                .output
                .get(index)
                .is_some()
                && self.inner_tx().outputs.get(index).is_some()
        );

        let txo = self.inner_tx().global.unsigned_tx.output.get(index)?;
        let prev_txout = UnvaultTxOut::new(txo.value, unvault_descriptor, to_pk_ctx);
        Some(UnvaultTxIn::new(
            OutPoint {
                txid: self.inner_tx().global.unsigned_tx.txid(),
                vout: index.try_into().expect("There are two outputs"),
            },
            prev_txout,
            csv,
        ))
    }

    /// Get the CPFP txo to be referenced in a spending transaction
    pub fn cpfp_txin<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        &self,
        cpfp_descriptor: &CpfpDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
    ) -> Option<CpfpTxIn> {
        let spk = cpfp_descriptor.0.script_pubkey(to_pk_ctx);
        let index = self
            .inner_tx()
            .global
            .unsigned_tx
            .output
            .iter()
            .position(|txo| txo.script_pubkey == spk)?;

        // If we don't have both at this point, there is a consequent logic error..
        debug_assert!(
            self.inner_tx()
                .global
                .unsigned_tx
                .output
                .get(index)
                .is_some()
                && self.inner_tx().outputs.get(index).is_some()
        );

        let txo = self.inner_tx().global.unsigned_tx.output.get(index)?;
        let prev_txout = CpfpTxOut::new(txo.value, cpfp_descriptor, to_pk_ctx);
        Some(CpfpTxIn::new(
            OutPoint {
                txid: self.inner_tx().global.unsigned_tx.txid(),
                vout: index.try_into().expect("There are two outputs"),
            },
            prev_txout,
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
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        unvault_input: UnvaultTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        vault_descriptor: &VaultDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
        lock_time: u32,
    ) -> CancelTransaction {
        // First, create a dummy transaction to get its weight without Witness. Note that we always
        // account for the weight *without* feebump input. It pays for itself.
        let vault_txo = VaultTxOut::new(u64::MAX, vault_descriptor, to_pk_ctx);
        let dummy_tx = create_tx!(
            [(unvault_input.clone(), SigHashType::AllPlusAnyoneCanPay)],
            [vault_txo],
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

        // Now, get the revaulting output value out of it.
        let unvault_value = unvault_input.txout().txout().value;
        let revault_value = unvault_value
            .checked_sub(fees)
            .expect("We would not create a dust unvault txo");
        let vault_txo = VaultTxOut::new(revault_value, vault_descriptor, to_pk_ctx);

        CancelTransaction(if let Some(feebump_input) = feebump_input {
            create_tx!(
                [
                    (unvault_input, SigHashType::AllPlusAnyoneCanPay),
                    (feebump_input, SigHashType::All),
                ],
                [vault_txo],
                lock_time,
            )
        } else {
            create_tx!(
                [(unvault_input, SigHashType::AllPlusAnyoneCanPay)],
                [vault_txo],
                lock_time,
            )
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
    /// Will error **only** when trying to spend a dust deposit.
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new(
        vault_input: VaultTxIn,
        feebump_input: Option<FeeBumpTxIn>,
        emer_address: EmergencyAddress,
        lock_time: u32,
    ) -> Result<EmergencyTransaction, Error> {
        // First, create a dummy transaction to get its weight without Witness. Note that we always
        // account for the weight *without* feebump input. It has to pay for itself.
        let emer_txo = EmergencyTxOut::new(emer_address.clone(), u64::MAX);
        let dummy_tx = create_tx!(
            [(vault_input.clone(), SigHashType::AllPlusAnyoneCanPay)],
            [emer_txo],
            lock_time,
        )
        .global
        .unsigned_tx;

        // The weight of the emergency transaction without a feebump input is the weight of the
        // witness-stripped transaction plus the weight required to satisfy the vault txin
        let total_weight = dummy_tx
            .get_weight()
            .checked_add(vault_input.max_sat_weight())
            .expect("Weight computation bug");
        let total_weight: u64 = total_weight.try_into().expect("usize in u64");
        let fees = REVAULTING_TX_FEERATE
            .checked_mul(total_weight)
            .expect("Weight computation bug");
        // Without the feebump input, it should not be reachable.
        debug_assert!(fees < INSANE_FEES);

        // Now, get the emergency output value out of it.
        let deposit_value = vault_input.txout().txout().value;
        let emer_value = deposit_value.checked_sub(fees).ok_or_else(|| {
            Error::TransactionCreation("Creating an emergency tx for a dust deposit?".to_string())
        })?;
        let emer_txo = EmergencyTxOut::new(emer_address, emer_value);

        Ok(EmergencyTransaction(
            if let Some(feebump_input) = feebump_input {
                create_tx!(
                    [
                        (vault_input, SigHashType::AllPlusAnyoneCanPay),
                        (feebump_input, SigHashType::All)
                    ],
                    [emer_txo],
                    lock_time,
                )
            } else {
                create_tx!(
                    [(vault_input, SigHashType::AllPlusAnyoneCanPay)],
                    [emer_txo],
                    lock_time,
                )
            },
        ))
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
}

impl_revault_transaction!(
    SpendTransaction,
    doc = "The transaction spending the unvaulting transaction, paying to one or multiple \
    externally-controlled addresses, and possibly to a new vault txo for the change."
);
impl SpendTransaction {
    /// A spend transaction can batch multiple unvault txouts, and may have any number of
    /// txouts (destination and change) in addition to the CPFP one..
    ///
    /// BIP174 Creator and Updater roles.
    pub fn new<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        unvault_inputs: Vec<UnvaultTxIn>,
        spend_txouts: Vec<SpendTxOut>,
        cpfp_descriptor: &CpfpDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
        lock_time: u32,
    ) -> SpendTransaction {
        // The spend transaction CPFP output value depends on its size. See practical-revault for
        // more details. Here we append a dummy one, and we'll modify it in place afterwards.
        let dummy_cpfp_txo = CpfpTxOut::new(u64::MAX, &cpfp_descriptor, to_pk_ctx);

        // Record the satisfaction cost before moving the inputs
        let sat_weight: u64 = unvault_inputs
            .iter()
            .map(|txin| txin.max_sat_weight())
            .sum::<usize>()
            .try_into()
            .expect("An usize doesn't fit in an u64?");

        let mut txos = Vec::with_capacity(spend_txouts.len() + 1);
        txos.push(dummy_cpfp_txo.txout().clone());
        txos.extend(spend_txouts.iter().map(|spend_txout| match spend_txout {
            SpendTxOut::Destination(ref txo) => txo.clone().into_txout(),
            SpendTxOut::Change(ref txo) => txo.clone().into_txout(),
        }));

        // For the PsbtOut s
        let mut txos_wit_script = Vec::with_capacity(spend_txouts.len() + 1);
        txos_wit_script.push(dummy_cpfp_txo.into_witness_script());
        txos_wit_script.extend(
            spend_txouts
                .into_iter()
                .map(|spend_txout| match spend_txout {
                    SpendTxOut::Destination(txo) => txo.into_witness_script(), // None
                    SpendTxOut::Change(txo) => txo.into_witness_script(),
                }),
        );

        let mut psbt = Psbt {
            global: PsbtGlobal {
                unsigned_tx: Transaction {
                    version: 2,
                    lock_time,
                    input: unvault_inputs
                        .iter()
                        .map(|input| input.unsigned_txin())
                        .collect(),
                    output: txos,
                },
                unknown: BTreeMap::new(),
            },
            inputs: unvault_inputs
                .into_iter()
                .map(|input| {
                    let prev_txout = input.into_txout();
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

        // We only need to modify the unsigned_tx global's output value as the PSBT outputs only
        // contain the witness script.
        let witstrip_weight: u64 = psbt.global.unsigned_tx.get_weight().try_into().unwrap();
        let total_weight = sat_weight
            .checked_add(witstrip_weight)
            .expect("Weight computation bug");
        // See https://github.com/re-vault/practical-revault/blob/master/transactions.md#cancel_tx
        // for this arbirtrary value.
        let cpfp_value = 2 * 32 * total_weight;
        // We could just use output[0], but be careful.
        let mut cpfp_txo = psbt
            .global
            .unsigned_tx
            .output
            .iter_mut()
            .find(|txo| txo.script_pubkey == cpfp_descriptor.0.script_pubkey(to_pk_ctx))
            .expect("We just created it!");
        cpfp_txo.value = cpfp_value;

        SpendTransaction(psbt)
    }
}

/// The funding transaction, we don't create nor sign it.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultTransaction(pub Transaction);
impl VaultTransaction {
    /// Assumes that the outpoint actually refers to this transaction. Will panic otherwise.
    pub fn vault_txin<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
        &self,
        outpoint: OutPoint,
        deposit_descriptor: &VaultDescriptor<Pk>,
        to_pk_ctx: ToPkCtx,
    ) -> VaultTxIn {
        assert!(outpoint.txid == self.0.txid());
        let txo = self.0.output[outpoint.vout as usize].clone();

        VaultTxIn::new(
            outpoint,
            VaultTxOut::new(txo.value, deposit_descriptor, to_pk_ctx),
        )
    }
}

/// The fee-bumping transaction, we don't create nor sign it.
#[derive(Debug, Clone, PartialEq)]
pub struct FeeBumpTransaction(pub Transaction);

/// Get the entire chain of pre-signed transaction out of a deposit. No feebump input.
pub fn transaction_chain<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
    deposit_txin: VaultTxIn,
    vault_descriptor: &VaultDescriptor<Pk>,
    unvault_descriptor: &UnvaultDescriptor<Pk>,
    cpfp_descriptor: &CpfpDescriptor<Pk>,
    emer_address: EmergencyAddress,
    to_pk_ctx: ToPkCtx,
    lock_time: u32,
    unvault_csv: u32,
) -> Result<
    (
        UnvaultTransaction,
        CancelTransaction,
        EmergencyTransaction,
        UnvaultEmergencyTransaction,
    ),
    Error,
> {
    let unvault_tx = UnvaultTransaction::new(
        deposit_txin.clone(),
        &unvault_descriptor,
        &cpfp_descriptor,
        to_pk_ctx,
        lock_time,
    )?;
    let cancel_tx = CancelTransaction::new(
        unvault_tx
            .unvault_txin(&unvault_descriptor, to_pk_ctx, unvault_csv)
            .expect("We just created it."),
        None,
        &vault_descriptor,
        to_pk_ctx,
        lock_time,
    );
    let emergency_tx =
        EmergencyTransaction::new(deposit_txin, None, emer_address.clone(), lock_time)?;
    let unvault_emergency_tx = UnvaultEmergencyTransaction::new(
        unvault_tx
            .unvault_txin(&unvault_descriptor, to_pk_ctx, unvault_csv)
            .expect("We just created it."),
        None,
        emer_address,
        lock_time,
    );

    Ok((unvault_tx, cancel_tx, emergency_tx, unvault_emergency_tx))
}

/// Get a spend transaction out of a list of deposits.
pub fn spend_tx_from_deposit<ToPkCtx: Copy, Pk: MiniscriptKey + ToPublicKey<ToPkCtx>>(
    deposit_txins: Vec<VaultTxIn>,
    spend_txos: Vec<SpendTxOut>,
    unvault_descriptor: &UnvaultDescriptor<Pk>,
    cpfp_descriptor: &CpfpDescriptor<Pk>,
    to_pk_ctx: ToPkCtx,
    unvault_csv: u32,
    lock_time: u32,
) -> Result<SpendTransaction, Error> {
    let unvault_txins = deposit_txins
        .into_iter()
        .map(|dep| {
            UnvaultTransaction::new(
                dep,
                &unvault_descriptor,
                &cpfp_descriptor,
                to_pk_ctx,
                lock_time,
            )
            .and_then(|unvault_tx| {
                Ok(unvault_tx
                    .unvault_txin(&unvault_descriptor, to_pk_ctx, unvault_csv)
                    .expect("We just created it"))
            })
        })
        .collect::<Result<Vec<UnvaultTxIn>, Error>>()?;

    Ok(SpendTransaction::new(
        unvault_txins,
        spend_txos,
        cpfp_descriptor,
        to_pk_ctx,
        lock_time,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        CancelTransaction, EmergencyAddress, EmergencyTransaction, FeeBumpTransaction,
        RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
        VaultTransaction, RBF_SEQUENCE,
    };
    use crate::{scripts::*, txins::*, txouts::*, Error};

    use std::str::FromStr;

    use miniscript::{
        bitcoin::{
            secp256k1,
            secp256k1::rand::{rngs::SmallRng, FromEntropy, RngCore},
            util::bip32,
            Address, Network, OutPoint, SigHash, SigHashType, Transaction, TxIn, TxOut,
        },
        descriptor::{DescriptorPublicKey, DescriptorXKey},
        Descriptor, DescriptorPublicKeyCtx, ToPublicKey,
    };

    fn get_random_privkey(rng: &mut SmallRng) -> bip32::ExtendedPrivKey {
        let mut rand_bytes = [0u8; 64];

        rng.fill_bytes(&mut rand_bytes);

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
        let mut rng = SmallRng::from_entropy();

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
                    is_wildcard: true,
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
                    is_wildcard: true,
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
                    is_wildcard: true,
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
                is_wildcard: child_number.is_some(),
            });
            let xpub_ctx = DescriptorPublicKeyCtx::new(
                &secp,
                // If the xpub is not a wildcard, it's not taken into account.......
                child_number.unwrap_or_else(|| bip32::ChildNumber::from(0)),
            );
            tx.add_signature(input_index, xpub.to_public_key(xpub_ctx), sig)?;
        }

        Ok(())
    }

    #[test]
    fn test_transaction_chain() {
        let secp = secp256k1::Secp256k1::new();
        let mut rng = SmallRng::from_entropy();
        // FIXME: if the CSV is high enough it would trigger a different error in the invalid
        // spend!
        // let csv = rng.next_u32() % (1 << 22);
        let csv = rng.next_u32() % (1 << 16);

        // Test the dust limit
        assert_eq!(
            transaction_chain(2, 1, csv, 234_631, &secp),
            Err(Error::TransactionCreation(
                "Deposit is 234631 sats but we need at least 4632 (fees) \
                    + 30000 (cpfp) + 200000 (dust limit)"
                    .to_string()
            ))
        );
        // Absolute minimum
        transaction_chain(2, 1, csv, 234_632, &secp).expect(&format!(
            "Tx chain with 2 stakeholders, 1 manager, {} csv, 235_250 deposit",
            csv
        ));
        // 1 BTC
        transaction_chain(8, 3, csv, 100_000_000, &secp).expect(&format!(
            "Tx chain with 8 stakeholders, 3 managers, {} csv, 1_000_000 deposit",
            csv
        ));
        // 100 000 BTC
        transaction_chain(8, 3, csv, 100_000_000_000_000, &secp).expect(&format!(
            "Tx chain with 8 stakeholders, 3 managers, {} csv, 100_000_000_000_000 deposit",
            csv
        ));
        // 100 BTC
        transaction_chain(38, 5, csv, 100_000_000_000, &secp).expect(&format!(
            "Tx chain with 38 stakeholders, 5 manager, {} csv, 100_000_000_000 deposit",
            csv
        ));
    }

    fn transaction_chain(
        n_stk: usize,
        n_man: usize,
        csv: u32,
        deposit_value: u64,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
    ) -> Result<(), Error> {
        // Let's get the 10th key of each
        let child_number = bip32::ChildNumber::from(10);
        let xpub_ctx = DescriptorPublicKeyCtx::new(&secp, child_number);

        // Keys, keys, keys everywhere !
        let (
            (managers_priv, managers),
            (stakeholders_priv, stakeholders),
            (cosigners_priv, cosigners),
        ) = get_participants_sets(n_stk, n_man, secp);

        // Get the script descriptors for the txos we're going to create
        let unvault_descriptor = unvault_descriptor(
            stakeholders.clone(),
            managers.clone(),
            managers.len(),
            cosigners.clone(),
            csv,
        )
        .expect("Unvault descriptor generation error");
        let cpfp_descriptor =
            cpfp_descriptor(managers).expect("Unvault CPFP descriptor generation error");
        let vault_descriptor =
            vault_descriptor(stakeholders).expect("Vault descriptor generation error");

        // We reuse the deposit descriptor for the emergency address
        let emergency_address = EmergencyAddress::from(Address::p2wsh(
            &vault_descriptor.0.witness_script(xpub_ctx),
            Network::Bitcoin,
        ))
        .expect("It's a P2WSH");

        // The funding transaction does not matter (random txid from my mempool)
        let vault_scriptpubkey = vault_descriptor.0.script_pubkey(xpub_ctx);
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
                value: deposit_value,
                script_pubkey: vault_scriptpubkey.clone(),
            }],
        };
        let vault_txo = VaultTxOut::new(vault_raw_tx.output[0].value, &vault_descriptor, xpub_ctx);
        let vault_tx = VaultTransaction(vault_raw_tx);

        // The fee-bumping utxo, used in revaulting transactions inputs to bump their feerate.
        // We simulate a wallet utxo.
        let mut rng = SmallRng::from_entropy();
        let feebump_xpriv = get_random_privkey(&mut rng);
        let feebump_xpub = bip32::ExtendedPubKey::from_private(&secp, &feebump_xpriv);
        let feebump_descriptor =
            Descriptor::<DescriptorPublicKey>::Wpkh(DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: feebump_xpub,
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
                script_pubkey: feebump_descriptor.script_pubkey(xpub_ctx),
            }],
        };
        let feebump_txo = FeeBumpTxOut::new(raw_feebump_tx.output[0].clone());
        let feebump_tx = FeeBumpTransaction(raw_feebump_tx);

        // Create and sign the first (vault) emergency transaction
        let vault_txin = VaultTxIn::new(
            OutPoint {
                txid: vault_tx.0.txid(),
                vout: 0,
            },
            vault_txo.clone(),
        );
        // We can sign the transaction without the feebump input
        let mut emergency_tx_no_feebump =
            EmergencyTransaction::new(vault_txin.clone(), None, emergency_address.clone(), 0)
                .unwrap();
        let value_no_feebump =
            emergency_tx_no_feebump.inner_tx().global.unsigned_tx.output[0].value;
        // 376 is the witstrip weight of an emer tx (1 segwit input, 1 P2WSH txout), 22 is the feerate is sat/WU
        assert_eq!(
            value_no_feebump + (376 + vault_txin.max_sat_weight() as u64) * 22,
            deposit_value,
        );
        // We cannot get a sighash for a non-existing input
        let sighash_err = emergency_tx_no_feebump.signature_hash(
            10,
            &vault_descriptor.0.witness_script(xpub_ctx),
            SigHashType::AllPlusAnyoneCanPay,
        );
        assert!(sighash_err
            .expect_err("Sighash wrong input")
            .to_string()
            .contains("out of bonds or psbt input has no witness utxo"));
        // But for an existing one, all good
        let emergency_tx_sighash_vault = emergency_tx_no_feebump.signature_hash(
            0,
            &vault_descriptor.0.witness_script(xpub_ctx),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
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
        assert!(err
            .expect_err("No error for invalid sighash ?")
            .to_string()
            .contains("Unexpected sighash type for psbtin:"));
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
        let mut emergency_tx =
            EmergencyTransaction::new(vault_txin, Some(feebump_txin), emergency_address.clone(), 0)
                .unwrap();
        let emergency_tx_sighash_feebump = emergency_tx.signature_hash(
            1,
            &feebump_descriptor.script_code(xpub_ctx),
            SigHashType::All,
        )?;
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
        let vault_txin = VaultTxIn::new(
            OutPoint {
                txid: vault_tx.0.txid(),
                vout: 0,
            },
            vault_txo.clone(),
        );
        let vault_txin_sat_cost = vault_txin.max_sat_weight();
        let unvault_txo = UnvaultTxOut::new(7000, &unvault_descriptor, xpub_ctx);
        let mut unvault_tx = UnvaultTransaction::new(
            vault_txin,
            &unvault_descriptor,
            &cpfp_descriptor,
            xpub_ctx,
            0,
        )?;
        let unvault_value = unvault_tx.inner_tx().global.unsigned_tx.output[0].value;
        // 548 is the witstrip weight of an unvault tx (1 segwit input, 2 P2WSH txouts), 6 is the
        // feerate is sat/WU, and 30_000 is the CPFP output value.
        assert_eq!(
            unvault_value + (548 + vault_txin_sat_cost as u64) * 6 + 30_000,
            deposit_value,
        );

        // Create and sign the cancel transaction
        let unvault_txin = unvault_tx
            .unvault_txin(&unvault_descriptor, xpub_ctx, RBF_SEQUENCE)
            .unwrap();
        assert_eq!(unvault_txin.txout().txout().value, unvault_value);
        // We can create it entirely without the feebump input
        let mut cancel_tx_without_feebump =
            CancelTransaction::new(unvault_txin.clone(), None, &vault_descriptor, xpub_ctx, 0);
        // Keep track of the fees we computed..
        let value_no_feebump = cancel_tx_without_feebump
            .inner_tx()
            .global
            .unsigned_tx
            .output[0]
            .value;
        // 376 is the witstrip weight of a cancel tx (1 segwit input, 1 P2WSH txout), 22 is the feerate is sat/WU
        assert_eq!(
            value_no_feebump + (376 + unvault_txin.max_sat_weight() as u64) * 22,
            unvault_txin.txout().txout().value,
        );
        let cancel_tx_without_feebump_sighash = cancel_tx_without_feebump.signature_hash(
            0,
            &unvault_descriptor.0.witness_script(xpub_ctx),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
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
            unvault_txin,
            Some(feebump_txin),
            &vault_descriptor,
            xpub_ctx,
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
        let cancel_tx_sighash_feebump = cancel_tx.signature_hash(
            1,
            &feebump_descriptor.script_code(xpub_ctx),
            SigHashType::All,
        )?;
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

        // Create and sign the second (unvault) emergency transaction
        let unvault_txin = unvault_tx
            .unvault_txin(&unvault_descriptor, xpub_ctx, RBF_SEQUENCE)
            .unwrap();
        // We can create it without the feebump input
        let mut unemergency_tx_no_feebump = UnvaultEmergencyTransaction::new(
            unvault_txin.clone(),
            None,
            emergency_address.clone(),
            0,
        );
        let value_no_feebump = unemergency_tx_no_feebump
            .inner_tx()
            .global
            .unsigned_tx
            .output[0]
            .value;
        // 376 is the witstrip weight of an emer tx (1 segwit input, 1 P2WSH txout), 22 is the feerate is sat/WU
        assert_eq!(
            value_no_feebump + (376 + unvault_txin.max_sat_weight() as u64) * 22,
            unvault_txin.txout().txout().value,
        );
        let unemergency_tx_sighash = unemergency_tx_no_feebump.signature_hash(
            0,
            &unvault_descriptor.0.witness_script(xpub_ctx),
            SigHashType::AllPlusAnyoneCanPay,
        )?;
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
            unvault_txin,
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
        let unemer_tx_sighash_feebump = unemergency_tx.signature_hash(
            1,
            &feebump_descriptor.script_code(xpub_ctx),
            SigHashType::All,
        )?;
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
        let unvault_tx_sighash = unvault_tx.signature_hash(
            0,
            &vault_descriptor.0.witness_script(xpub_ctx),
            SigHashType::All,
        )?;
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
        let unvault_txin = unvault_tx
            .unvault_txin(&unvault_descriptor, xpub_ctx, csv - 1) // Off-by-one
            .unwrap();
        let spend_txo = ExternalTxOut::new(TxOut {
            value: 1,
            ..TxOut::default()
        });
        // Test satisfaction failure with a wrong CSV value
        let mut spend_tx = SpendTransaction::new(
            vec![unvault_txin],
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &cpfp_descriptor,
            xpub_ctx,
            0,
        );
        let spend_tx_sighash = spend_tx.signature_hash(
            0,
            &unvault_descriptor.0.witness_script(xpub_ctx),
            SigHashType::All,
        )?;
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
        match spend_tx.finalize(&secp) {
            Err(e) => assert!(
                e.to_string().contains("could not satisfy at index 0"),
                "Invalid error: got '{}'",
                e
            ),
            Ok(_) => unreachable!(),
        }

        // "This time for sure !"
        let unvault_txin = unvault_tx
            .unvault_txin(&unvault_descriptor, xpub_ctx, csv) // Right csv
            .unwrap();
        let mut spend_tx = SpendTransaction::new(
            vec![unvault_txin],
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &cpfp_descriptor,
            xpub_ctx,
            0,
        );
        let spend_tx_sighash = spend_tx.signature_hash(
            0,
            &unvault_descriptor.0.witness_script(xpub_ctx),
            SigHashType::All,
        )?;
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
        let unvault_txins = vec![
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "0ed7dc14fe8d1364b3185fa46e940cb8e858f8de32e63f88353a2bd66eb99e2a:0",
                )
                .unwrap(),
                unvault_txo.clone(),
                csv,
            ),
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "23aacfca328942892bb007a86db0bf5337005f642b3c46aef50c23af03ec333a:1",
                )
                .unwrap(),
                unvault_txo.clone(),
                csv,
            ),
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "fccabf4077b7e44ba02378a97a84611b545c11a1ef2af16cbb6e1032aa059b1d:0",
                )
                .unwrap(),
                unvault_txo.clone(),
                csv,
            ),
            UnvaultTxIn::new(
                OutPoint::from_str(
                    "71dc04303184d54e6cc2f92d843282df2854d6dd66f10081147b84aeed830ae1:0",
                )
                .unwrap(),
                unvault_txo.clone(),
                csv,
            ),
        ];
        let n_txins = unvault_txins.len();
        let mut spend_tx = SpendTransaction::new(
            unvault_txins,
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &cpfp_descriptor,
            xpub_ctx,
            0,
        );
        for i in 0..n_txins {
            let spend_tx_sighash = spend_tx.signature_hash(
                i,
                &unvault_descriptor.0.witness_script(xpub_ctx),
                SigHashType::All,
            )?;
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
        unvault_tx.hex().expect("Hex repr unvault_tx");
        spend_tx.hex().expect("Hex repr spend_tx");
        cancel_tx.hex().expect("Hex repr cancel_tx");
        emergency_tx.hex().expect("Hex repr emergency_tx");

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

    // Just a small sanity check against bitcoind's converttopsbt and finalizepsbt
    #[cfg(feature = "use-serde")]
    #[test]
    fn test_deserialize_psbt() {
        let emergency_psbt_str = "\"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\"";
        let emergency_tx: EmergencyTransaction = serde_json::from_str(&emergency_psbt_str).unwrap();
        assert_eq!(emergency_tx.hex().unwrap().as_str(), "020000000001021a332b693f957337550f80a1c5df33a6d361656ad431bc930184fda67495ffdb0000000000fdffffff874c9b51a61389439cae8b3a56c2458179e0b92628ca13b72d675e74594559420000000000fdffffff01c201000000000000000a0048304502210097ccce07c83c25246e612212c25439aa8373a6d8ba1e5821def424efc1f2123502203ce2596f255e3279b558b15a2ff90861aa67e901029bc84227b9dcc794607b9581483045022100c805af0b1a2b317476f140cdf044a70b19596afae433c7d100b070f8159b16100220302887cb1de4576f02fe6d0cae9c89a4b2da8b509f0c77d2c5be4ff3617cd92181483045022100e5bb43af9c1dad6d1a53663bf4b85a6e57f3dbd67bc3664097fca52c932307d302204897b75116f2f25f766114cca6adb5f1e5ff0c53d51834d23c5c86f29501f35081483045022100806d035bd06675c75c5d5e13959c1f7ba217bfc9a665646279390dcfdf7764d602207a852818f78c7984b251f8fefdb09c60d2f3f822c40088a16a413d026a0dccb981483045022100dc86c5d2d2c562cf5419a6ed65d6ee1c51741cdbb3302a2c91ec0b1b756341e9022052a80075227f3f30877d0f074fb1fc56404bacf9a47bf0b56de2bdef3a00c66581483045022100ad70b6dcbe2b0da7c466c268dd3c10e0d99e69b871a989be70c53857e3fe2d3d02207aaa86f0e07ce7a92c71222b283fbfbfcdc9fec2d39fd12e7ad1752ef8d69ef881483045022100e79061c8b06ea83386602b2350f3798a9cd03a624e6cd534eff18e1b19745ff102200d9906c1464d0dfc1788deb2ff31496e1ff53de96627c0af04c31cda68ebd2658147304402205be5f2861931f3b4f2dcf60eb30a890675fcbea89adf537740e5d507eccb75a202202a1b79229d313b09492f01206a5822afbab47865b651d7ad122e00da1f9b162c81fd130158210212b0f7c8dbd822defaf04863b1036218d09f4205b05a1b48b2f593e483f7a4f42102238f8f668ba39759a2e128b45e3e9a76a3625ee6b79610345c349cc5ee9b2eee2103123104586c00ea984b5b6048a4ed9ecfe788e2808c71632a3816de32eac4477c21027f973801f1793fca53d24a4edafcbce2cc8e5efa748c8d8cf3b9d0a71f516ca421021bffbf5c038953eb6a664e41876704bc41651a17411f1ac45bb40dedbb1cd61e2103eed74c020422cffe2ee0e46ae2502a71ca788121582b9499fe6e252c7722f8032103244685c918e3897f7499ecfaa7680c0f46ff1e29fe106efbbd1cc49ffdd5717c2102044834de773f158080a98a12c509a1e236eaab8fa9a45bdf6b2e9b7714b9205258ae0247304402204e8de6b4d8a445b83b2f7ae5fd0c80eab0238ba181e590097dbe1dd5cd18dea4022007537a770b3fc54a045c41d85c0567e20dd84872cbb3ada84a262b8152fd81a6012102fff7dfadab827a291e5b71c78106e3b6cdf891c2ccce6da80586a9560d262e1400000000");

        let unvault_psbt_str = "\"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\"";
        let unvault_tx: UnvaultTransaction = serde_json::from_str(&unvault_psbt_str).unwrap();
        assert_eq!(unvault_tx.hex().unwrap().as_str(), "020000000001019b3a73b5855b56c45f4df3d6889220a0e4a0c892bd88caf1a4d9acf01eeff23e0000000000ffffffff02581b000000000000220020bd591d245b0608c62c222f7eae74b80e6bc792755087ff8ef3f27eb759241d0d4a01000000000000220020e924c238d67588a1f1725d49d3ddd4b5a60391ea56f5b9275481a35c88686c010a00483045022100dec2dc9836c8b1adae4cb16302c6f147a260162b1f9736b5dc24b06699c27fec02202fd17368b3ec13a1da26aab1e0b3653942049cabb31526efb54088b9a4a074070147304402204b79fb0954e8f1d3bfcc0c59ff3b4e3d3057c5bedbbe655ac8e0c3f39c243a19022059aa14c014282d3d0ddb22d2e3ad94c5eaf9c7ec0e3efb9e8258e3a2f54af9f5014730440220799aa475ab43756f08390684e618f19519eabce4035af80c16aac21cd1dc3fab0220558380f319f2a2a8a79bdd13e877253a4e53e40c5127f55071bd41eeaf2e1b830147304402207b5c8fcc7238f07c97f5fb0a013c62b7875ade5acf2cec1d71182816adf05ee80220102fdf0d14371f55c474759ba92007d22002dd17c0afcfaf1fd33070aec675a4014830450221009473d697190e603624b35a3ce9f66092a50fcfb723e22ec74bbca87b90e6016d0220267bec58f7f7fb2f68a28874ed562b9e798f7ec8df2b2e9386c8521e9a9e88e80147304402201d7eb6c7bfcafe13d9d9501779c45bc615caa5b20a87a75e1928e1015e4f31010220227094c14fe75cdf722f04e3dae7452fbebc66e325a0b4861b06a55d732daebc014830450221008e953b06c230cf375d8311dc377621516d505473573e36e7b7e342fa59d9cdc6022030446435c01f5c30dfd12ab0333c49c86b4df300f43758822117f7df9cdeaa1d014830450221008939f652f669ab7ddf33f45950ad4bae2d1b0fadc3d089b8b21ce20c4dff4e6b022069e5fd94e176536e381123171c671e37f5a12f299b47527557239d8487340ab001fd13015821038145c3332deca3df3f7e0f52eb99c584ef523f1192a30a94aa36702e10698e092102ee50919fb05cb05c39e939ea6cef0f119d00a9445eb0a7d5e7c73309720db4a121039f30df3726826a62fdab707dd43903e704b0ecfb2ec18bae86b2992a4eb521d0210374ee54a2079629eed9d91aec84435a50ad50f1fde2d06ba61d0c4a2a161e760d21030f9af1d1e45414f51530729da40db01f68f013962a55ea88348c9534886fa3812102cb89e20c20ec9402835fcbbd5d77587e4f971ba3152aeb52413b61005a3646ed2103210793f1e32f48ca8bfeef15e1975a4167741bdf5f1b74c0ac505fe7774432ee2103f2f483e8c7cb5b59bd1e18794f5b385d148c16111e925a567a15c7dfcc921cdd58ae00000000");

        let cancel_psbt_str = "\"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\"";
        let cancel_tx: CancelTransaction = serde_json::from_str(&cancel_psbt_str).unwrap();
        assert_eq!(cancel_tx.hex().unwrap().as_str(), "02000000000102d7515eabf693641f4e98e51b495f826d224df2f5f6c09c2404fe42728cc6abfc0000000000fdffffff98348e8716ed04dbb99b01d015a37b4ded31107b169ae426192be428c2e5f9c70000000000fdffffff012c1a000000000000220020ab3315dfffde453ea67f8d06960a846b9afeaae31834fe610529a6c146b77b191547304402203d33233ee559fb361d2d7b22e1488751fd214c9cd90c0355215af333527ae48e0220412e3f2c1cda8c5fd958da6b5043187ec0b3f3de7dd913488450b58df9b7f70e812103ce9c09c582527a073e68eb477a44b50985f0189e388b74d93637a3e3f1086714483045022100e7d5d911927635deaa09456402392cbc443d7062c975e609e27864304cdd35dc022041a93e98b478a987baa9c8d7d73ab018b49244292e9b2bfb48cbefd1b35bc628812102b03887cb425e312fcb9f2a1d73563da957ed81b3755d400f8219e20d0743c788483045022100e9625e438dd8d2918fd62069e0ad2f56ef955e85df0f07498825a6480e3676a902204dfc8d9f78f347826f92f08d11637a120cddc2620290dc46522b36ae43ded5e38121028902824b9c23d4ea835b03bb952304e06d781cf2e200a2ed092665e7a82a17204730440220467324938eb35f77380e4bcb4db695e2b2012e37f886a6de4c7f9d7069ca3acb02202187a5fa4fbc557f4ea7354719437c8955e98655f877668de8ad44e587b040b78121039c75d214415700b23fa1f14e1bfdfb78af299c5b83ba2a3e32e286b7ac75a71a483045022100ec4a89973d40896eb314a02203eef88edc4ff571092bd2df98cb663e5db1ab7a022059ea06874691538a817e1c1e99b67022653ba7e995d714c36d933771d63faa878121036f7b55f7f54dc85048f9adecf37e947806c0e7bdf0ed4fee79eb359b637b60e748304502210084ea3de959ef15f570be3dee648dc23f95099a25f00aec237301d778f629c8db02205530466c4e36c36b14b10ed4d45b2574281e27f44cd339ec32735327dd60eda4812102bdda16bf511b06ff1c3f28d4eb5f446c14120306ede35e1b826d7605e6e4481f483045022100bdc60a855530198e81b8ae1d4f87c2fd5dd73d8ce21ebe545800a2ea1204b09f02207af1580f04550e8abdf2f196fa23339995ce5b05ca0f2370d54ffabedfa041408121035987348dfee82ccd4184c580f8a3dcf8021576d23b4db65c50165c0c359b0ead473044022007bf900dfc7755bcc2369d9920e45c720ff6da0f55bac2693fc23571f302ce7f02207c210dea715428e2dd54c62e102c2820dfe065ed10c3b311a1793c2b66c9b63c812103c2b595356f4355dc97550e93aef1fb76e81ab4ba004e12b1627b2c9e9d1fcd6600000000fd61025321032baac522ae66a1b8ab3550067b131d44e42717b67e61dc54c225a61411557e2e21021ff81c78703f6fbcac61326ea08fe2a9ee484cc5f0313b9f383f7a0ba5f76f3321026d17eed0e0772356d9ed90e165a268a467c6ef39834d97d317b2135a4979fcda53ae6476a914467edd3a1cd2901af6c244e6292f98bc346d08e388ac6b76a9148b05f6776ea9050f7f0b6b1cc20bc18e505e0c2f88ac6c936b76a9145d7188431a4541acafe4bc6d69e79dfb6e4baeda88ac6c936b76a914a6a982b681ebffb3d2f59696a2864686cae5c6c588ac6c936b76a9146a61eddf5da75be4a9a927a6badcd065e6555bf188ac6c936b76a914cd66f831d47bf6d399f7b700d79d09541202518888ac6c936b76a9147b24f0ed06c3d41de60153324f43e32a3d09b1f388ac6c936b76a9146fe70c0465f37377bd6581b5d4703724eea9ad2588ac6c9358876758210200f84cbd9c10a526f5261f7083689db944049fc2ced1f08acee989f89eab1a0421036223ce0f1e089eeceeb7d23cc90ea12019cb86e03b53d8486768a942d22e60df2103f655f9bd1b92b44c5256548e30397fe629374ab30a367a25fbd9ff430a9e883e21037eaa8ab21d0fe04a8f9611bd2667618d26e3155939542a896e2ca442ac012a512102f5c847f21c17b130a657b0dabb102ae2d7db0dc6f5c5e3db9949cee1a5c01caf21027514dd45e88f1aedec61f906cfaee084d8ffc91411cc136bcbd3ec3dda547d472102277f6465475f268f959749833e4436a0e9b9a207a32e3de330301634d1b50e6121022fe9c9c4ee7c391fac9ae1f6d7aee7ec1ba969cdee0e060f2028b057e116b97858af012ab26802473044022055ec85d596760aac21e646e6b1260a80a26d2d38409d5645849d6a650b230ed202201e70bf3b0b917eb6928baafd5015faca020bec2394ee318a2d1d0383812f915e012103581675fe63804b705cf1c100694ebfe85a08b6e5323429997f907b213af1432700000000");

        let unemergency_psbt_str = "\"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\"";
        let unemergency_tx: UnvaultEmergencyTransaction =
            serde_json::from_str(&unemergency_psbt_str).unwrap();
        assert_eq!(unemergency_tx.hex().unwrap().as_str(), "0200000000010214f44be11e0272e165a9ece61c319bb4d6395b29d08b90da6ebe46c25a1022ff0000000000fdffffff7963ba6ee8b62d8f30358b38056546eba13aaf2f38b275f4bd461b44cae7c65d0000000000fdffffff01c2010000000000000015473044022018fb473cc5f637c055b0e2d2c70a4b219727fb7d4a26cc1b5ae8ae54e98f89590220784afa48d2532d56086038981471251daf38da359b44f93b2b3c4b3208057cf481210350dc270973f90c4af06b59d139c5f5364b1d823d78b32af70ec663639cc3c152483045022100a568e5490a1f9ce3d69b463003ea5ae030557957e75d3d4cfb3de3292a9cf8770220079a00dfdb91349c20b516b81ad6bad22445b9d7a0394fc28338c52f15c7c2f4812102ff6757a06b36b90b3eddf5be626310d7f0b85f52d7b28033b873538c18b951c94830450221008e7451ef487786cd7c4ec20693d589f6fbeb045338025951b87ddacdd4d67b9a0220049481bea10e943bcbd67cbc2ec412a3b1b8e0ca8746e832f33eb80023c2f95e8121021cdad96978c3f2aaf20fc1eded79c61068793d20a26e7821cd96daa6f691a98047304402206884a3c7baf504d9fd957116ea46e1c9a4ed29211961438f234ee005c3683a1402203760e8d1d87f223f96aac56d1890ba29512c8af23f3c0c0aa4107129ee32d081812103bc74689157645fc100e9251328aa24093c95f1fecc27aa946da0e03f57e70105473044022100c7fb122d8aab67b2a706c9c3330f546a903b10659642db997c10335b4d600b41021f56a3d626136107441ab85603ded9bfe6a1cf44be57836cbc6bf0fabf0132078121025e1e96f25be6eb23f7e38f37028773d731b2d439c073fb81a057bde479a6b53148304502210093e9bbcbaf3b2e2bacfaeee13598faebea9513f392a5a6025b28a76e8ea339880220583707ead8d1e9ea5bad85a5a5792f9656ce61f01a71614f9c466913615e7e9681210208fd8c051227d3067ace7af4db67b577641c447a3540f80dadcc9117de143a94483045022100a5d47c738ee8c922b97a8d615031889526d15334a25323744f00d5485ce59fb2022034fdc08e014aad5e7cf572e6282d9c2c579cd53bbfac421fd6df8d7c4a4e1cec812102bcadb88ebba94ee24685fd56d6e2dfb4e47edb212bc0daa816d6f276ed9232cf483045022100d56c17b01314179581226baafbe6edc30f9ffcdda1a0ae77d7073ee8a05700d502203ae7bc5793d7b40c6f40e42a90192c7e5a879cadade76b648f5afd42e69514bc81210259fa94715eabdd80f63d03b05f600119537b947cf7b383ab865f13c6d68cb9c400000000fd6102532103febeb2444ee2305e8cecf8afeb902f3958819461ad3b2e38e2801b2a78ed237d210237b4063607eacc82d8e0d4b3ce00e54c02a7496eff5048d54a8962ced1f004212102694c3be234bfd78fd66bac42e8800d3e1799e05997046901b7add89bd4dbdfa753ae6476a914f8eb89147e8832358228a9ca65b865684aa6a52988ac6b76a914acb46f0a45af6077d3fb75f9a005d233eb96c8d788ac6c936b76a91440c99b3e4e8529c51454c57d820bac32bc3202d388ac6c936b76a9146339900692bf6f9c62ea675d30c61db3a1e52d6788ac6c936b76a914cbd1fae1a7f0f7c5ac573b7aa4143b9f5663565e88ac6c936b76a914a4e62fb7a5293349ae516633a1323343e68cfe9388ac6c936b76a9149387c4f41368a9dd268da057078c5bfc7f393cc588ac6c936b76a914a0aaf1218271febe3a288982be31ba7f9fafd95b88ac6c93588767582103f6a18836d45de765b260deebff60ebf4771887541b6328444e68509a94829b712102cd8bfc656b6193b3ab9afd76ff0953644cf7d52ea13c0e35911befcabe5fb31b2102cc0b3965cf7b9fb6ba4df302f6bccad2f3763624190dd26346fb3aea74862ccd210389cde09961cec4eee818c0c9d63e1bab9f9de4c27da0166ab86abf778411924b210372b8f3960614427ebbe17e52040b1fb9d75c0880023434ea7f587d29cba897122102f587fdd89ed79f38a03b7de11e0880441f90e02d86b9f1686c0b01eb406a529c2102540d44d20601a751110bb25c78751aa32dc4595e33b3a413028366060bdbfee52103ce022f501a2c199130f7dfef37f7d26763d44fa16855e76c5b49f6a0ba3f098b58af012ab26802483045022100c95d080065106a9c4abf0f9e3332a0a47ae7c82de708be3339f84096d0c7c8fd022069d62614f26fea26b8de9fa0593727f0b2eb4d290560a41c8f6467b6b76c9b720121039dde8752a6842dd373e3cf6919361d5d9b3fd6cdc3e67da041b139b122dbc67700000000");

        let spend_psbt_str = "\"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\"";
        let spend_tx: SpendTransaction = serde_json::from_str(&spend_psbt_str).unwrap();
        assert_eq!(spend_tx.hex().unwrap().as_str(), "020000000001013fbd48abbbaff0f47e45bbb56b59729c01353274261ef362bb905bfa4c3c922600000000002a000000010100000000000000000e0047304402201689048821f8d2e19070d8c923d8050f32763f2b5b817718d36cb0e9b3391c6c02206a51a74a477c6dbdf668041695dfeeb3818ca755a1dfa639933eaf0a6b148c4401483045022100dce35060727c3efff7cf6b6e9e95ee3ef4b34262235cf4547be3d0b4c494b7e1022036c1746e66840da42ac6e10ac68f121f3a322a35ec97704a57844bbc645f71cf0148304502210084d0a11d3225ef310a7ad139c20ce58dd8200378fdf559e9f49e9e7a019553430220467fa848d7c7a0562f9ef1ac3a6901942d854b648cac52175fdbb7d1ba5cb54201483045022100d2f812f888cedd419bd37f8dcc4b356152599e643ab2774d6a2f795a631dd18102204ee07af01ce41747d941d9754a6682bd9cf3525d58d8ba79cd3b989bc07631f901473044022055d7c1a9c5c8473cd37cf9e0c1ec8be51c6c58597799c3a00233396f6050a5f602200c9b57e47fa264615028ea90460fb2adc647b02e0c50c20081044f0ec28b5f630147304402203550478fa002f4aa291355cfbdd16e084c36041024a5bc4fde5211cedb3bc7f8022050e4c4c5c6e3e5c695a7567839e4a2666f36bf38246e6f6384d29436f2cb128801483045022100b76285e86453dc512bdbc3780027fc97ac7ef67c8c8ce06c19a2c0f64d275f5b0220673b91160f61e5f86450af83cc7e94f143781388cfdea1b06852c29b8be16b5101473044022046231442583f4e3c6340c40a07c3dfde733a2ad1180b45c6ad2e3029d812827e022047408c5bc97a4e6235e514cf36eac77a552cdb991f527dd523d5a99e03658bfb0100473044022034a05cede2eba2c7df83c3a95b0507919f85fff8f167427e6fb7eb72736adfb5022068c32a9c1c1e76a2382c6a3289b49093dc39373cc1ab5f7a5bcd9cccbe60d06901483045022100d70caf4feceb4c4b496c3fb05d3a26375ac71c0322f72ad47ecb593dd528f8bc02200acf326a875b7795b543d1b07208ef62643ece503cb0b025a18efb9b88b99f6801483045022100facea3fa8bf176ecfe7134ee842e366b486da363cf411d06aa8acd0d208c99050220108234eb819eae58afd924d3ae77fee34c1fc388dae43bf7bacd2bb36ac4fd6501fd61025321037b52d33ff20fa0a47bf34e887a8670d2a575487d37f5a6157346fc10ae0eaa9821022c6691dfd8830cc4a9b4b0ffedcf08efe7532615f381eb2796169141bdcf36a92102709c1908e86672384f5a60ca509fff9036a5618c0e6f069776251df58602d95353ae6476a91496e098b068ef07079269f99bae1ffd207aed7f6c88ac6b76a914926af51bc3e0b90d3aac23d2c010e10598c9541d88ac6c936b76a91480ef6a7a35e7c4a6c1c54727866e2537d8b7c4b288ac6c936b76a91486f88ffb60e2ec97cb496e797c88bfd9c3e66de488ac6c936b76a914403e8f0043551d0d6d1673d07e873a3f7fc8072a88ac6c936b76a914fc5b6355e58e414d0a26f91eff61c1695ac61c2588ac6c936b76a91483be70b016d599d72dd94df3af69d1da9e7084b088ac6c936b76a914b69f28fd01cb519c0e735d001e3b1d75745bba8088ac6c93588767582103f243852e1daa37727d9605e272bb0f027bd31023cf40a21327cbedebde1c5ea121021760a89fac1cb534a0b58e9056a35ab1383c45b68bc59c4cb5ac15f6248f4f432103865648e09923bd9e45dc0eecbf2883a9c210c4c813e140bfe6b60c7c53830ebc21026f96691f96828dd92e327a2f22b0797644d927055d5b50da8358f6db6dfc169f2102bdb89cf361a3f4b095238a1d5c63cb6a9cdea02f76974a618d6899d58aa117542103e227db0776e47c1480a49a92eeb205c02f96d6ece7d31740871c2b47acb32fcd2103ae448b8103bc9140960b38fb6ef1a2640b9bdfee8f9cfa9721b7be4a9bd1fd3e21033666b1de0fb71ccad84d45c3ccf5ea7028ddb59e6a53f3a4d7a139f9e7f91d9658af012ab26800000000");
    }
}
