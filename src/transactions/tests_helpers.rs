use super::{
    transaction_chain, CancelTransaction, CpfpTransaction, CpfpableTransaction, DepositTransaction,
    EmergencyAddress, EmergencyTransaction, RevaultPresignedTransaction, RevaultTransaction,
    SpendTransaction, UnvaultEmergencyTransaction, UnvaultTransaction, CPFP_MIN_CHANGE,
    DEPOSIT_MIN_SATS,
};

use crate::{error::*, scripts::*, txins::*, txouts::*};

use std::{iter::repeat_with, str::FromStr};

use miniscript::{
    bitcoin::{
        secp256k1,
        util::psbt::PartiallySignedTransaction as Psbt,
        util::{bip143::SigHashCache, bip32},
        Address, Amount, Network, OutPoint, SigHash, SigHashType, Transaction, TxIn, TxOut,
    },
    descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
    Descriptor, DescriptorTrait, MiniscriptKey,
};

fn get_random_privkey(rng: &mut fastrand::Rng) -> bip32::ExtendedPrivKey {
    let rand_bytes: Vec<u8> = repeat_with(|| rng.u8(..)).take(64).collect();

    bip32::ExtendedPrivKey::new_master(Network::Bitcoin, &rand_bytes)
        .unwrap_or_else(|_| get_random_privkey(rng))
}

// This generates the master private keys to derive directly from master, so it's
// [None]<xpub_goes_here>m/* descriptor pubkeys
fn get_participants_sets(
    n_stk: usize,
    n_man: usize,
    with_cosig_servers: bool,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) -> (
    (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
    (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
    (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
    (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
) {
    let mut rng = fastrand::Rng::new();

    let mut managers_priv = Vec::with_capacity(n_man);
    let mut managers = Vec::with_capacity(n_man);
    let mut mancpfp_priv = Vec::with_capacity(n_man);
    let mut mancpfp = Vec::with_capacity(n_man);
    for i in 0..n_man {
        managers_priv.push(get_random_privkey(&mut rng));
        managers.push(DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, &managers_priv[i]),
            derivation_path: bip32::DerivationPath::from(vec![]),
            wildcard: Wildcard::Unhardened,
        }));

        mancpfp_priv.push(get_random_privkey(&mut rng));
        mancpfp.push(DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, &mancpfp_priv[i]),
            derivation_path: bip32::DerivationPath::from(vec![]),
            wildcard: Wildcard::Unhardened,
        }));
    }

    let mut stakeholders_priv = Vec::with_capacity(n_stk);
    let mut stakeholders = Vec::with_capacity(n_stk);
    let mut cosigners_priv = Vec::with_capacity(n_stk);
    let mut cosigners = Vec::with_capacity(n_stk);
    for i in 0..n_stk {
        stakeholders_priv.push(get_random_privkey(&mut rng));
        stakeholders.push(DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, &stakeholders_priv[i]),
            derivation_path: bip32::DerivationPath::from(vec![]),
            wildcard: Wildcard::Unhardened,
        }));

        if with_cosig_servers {
            cosigners_priv.push(get_random_privkey(&mut rng));
            cosigners.push(DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: bip32::ExtendedPubKey::from_private(&secp, &cosigners_priv[i]),
                derivation_path: bip32::DerivationPath::from(vec![]),
                wildcard: Wildcard::Unhardened,
            }));
        }
    }

    (
        (managers_priv, managers),
        (mancpfp_priv, mancpfp),
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
    child_number: bip32::ChildNumber,
) -> Result<(), Error> {
    let derivation_path = bip32::DerivationPath::from(vec![child_number]);

    for xpriv in xprivs {
        let sig = secp.sign(
            &secp256k1::Message::from_slice(&tx_sighash).unwrap(),
            &xpriv
                .derive_priv(&secp, &derivation_path)
                .unwrap()
                .private_key
                .key,
        );

        let xpub = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, xpriv),
            derivation_path: bip32::DerivationPath::from(vec![]),
            wildcard: Wildcard::Unhardened,
        });
        let key = xpub
            .derive(child_number.into())
            .derive_public_key(secp)
            .unwrap();

        tx.add_signature(input_index, key.key, sig, secp)?;
    }

    Ok(())
}

fn sign_psbt(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    input_index: usize,
    xprivs: &[bip32::ExtendedPrivKey],
    child_number: bip32::ChildNumber,
) {
    for xpriv in xprivs {
        let deriv_path = bip32::DerivationPath::from(vec![child_number]);
        let sig = {
            let prev_amount = psbt.inputs[input_index]
                .witness_utxo
                .as_ref()
                .unwrap()
                .value;
            let script_code = psbt.inputs[input_index].witness_script.as_ref().unwrap();
            let sighash = SigHashCache::new(&psbt.global.unsigned_tx).signature_hash(
                input_index,
                &script_code,
                prev_amount,
                SigHashType::All,
            );
            secp.sign(
                &secp256k1::Message::from_slice(&sighash).unwrap(),
                &xpriv
                    .derive_priv(&secp, &deriv_path)
                    .unwrap()
                    .private_key
                    .key,
            )
        };

        let xpub = bip32::ExtendedPubKey::from_private(&secp, xpriv);
        let pubkey = xpub.derive_pub(secp, &deriv_path).unwrap();
        let mut sig = sig.serialize_der().to_vec();
        sig.push(SigHashType::All.as_u32() as u8);
        psbt.inputs[input_index]
            .partial_sigs
            .insert(pubkey.public_key, sig);
    }
}

fn finalize_psbt(secp: &secp256k1::Secp256k1<impl secp256k1::Verification>, psbt: &mut Psbt) {
    miniscript::psbt::finalize(psbt, secp)
        .map_err(|e| Error::TransactionFinalisation(e.to_string()))
        .unwrap();
}

fn desc_san_check<P: MiniscriptKey>(desc: &Descriptor<P>) -> Result<(), ScriptCreationError> {
    match desc {
        Descriptor::Wsh(wsh) => wsh.sanity_check().map_err(|e| e.into()),
        _ => unreachable!(),
    }
}

macro_rules! roundtrip {
    ($tx:ident, $tx_type:ident) => {
        #[cfg(feature = "use-serde")]
        {
            let serialized_tx = serde_json::to_string(&$tx).unwrap();
            let deserialized_tx = serde_json::from_str(&serialized_tx).unwrap();
            assert_eq!($tx, deserialized_tx);
        }

        let serialized_tx = $tx.to_string();
        let deserialized_tx: $tx_type = FromStr::from_str(&serialized_tx).unwrap();
        assert_eq!($tx, deserialized_tx);
    };
}

/// Derive transactions for a given deployment configuration, asserting some invariants
pub fn derive_transactions(
    n_stk: usize,
    n_man: usize,
    csv: u32,
    deposit_prevout: OutPoint,
    deposit_value: u64,
    // Outpoint and amount of inputs of a Spend
    unvault_spends: Vec<(OutPoint, u64)>,
    with_cosig_servers: bool,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) -> Result<(), Error> {
    // Let's get the 10th key of each
    let child_number = bip32::ChildNumber::from(10);

    // Keys, keys, keys everywhere !
    let (
        (managers_priv, managers),
        (mancpfp_priv, mancpfp),
        (stakeholders_priv, stakeholders),
        (cosigners_priv, cosigners),
    ) = get_participants_sets(n_stk, n_man, with_cosig_servers, secp);

    // Get the script descriptors for the txos we're going to create
    let unvault_descriptor = UnvaultDescriptor::new(
        stakeholders.clone(),
        managers.clone(),
        managers.len(),
        cosigners.clone(),
        csv,
    )?;
    assert_eq!(unvault_descriptor.csv_value(), csv);
    let cpfp_descriptor = CpfpDescriptor::new(mancpfp)?;
    let deposit_descriptor = DepositDescriptor::new(stakeholders)?;

    desc_san_check(
        deposit_descriptor
            .derive(child_number.into(), &secp)
            .inner(),
    )?;
    desc_san_check(
        unvault_descriptor
            .derive(child_number.into(), &secp)
            .inner(),
    )?;
    desc_san_check(cpfp_descriptor.derive(child_number.into(), &secp).inner())?;

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
            previous_output: deposit_prevout,
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: deposit_value,
            script_pubkey: deposit_scriptpubkey.clone(),
        }],
    };
    let deposit_txo = DepositTxOut::new(
        Amount::from_sat(deposit_raw_tx.output[0].value),
        &der_deposit_descriptor,
    );
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
        secp,
    )?;

    // Create and sign the first (deposit) emergency transaction
    let mut emergency_tx =
        EmergencyTransaction::new(deposit_txin.clone(), emergency_address.clone())?;
    assert_eq!(h_emer, emergency_tx);
    assert_eq!(
        emergency_tx.emergency_outpoint(),
        OutPoint {
            txid: emergency_tx.txid(),
            vout: 0
        }
    );

    // 376 is the witstrip weight of an emer tx (1 segwit input, 1 P2WSH txout), 250 is the feerate is sat/WU
    assert_eq!(
        emergency_tx.fees(),
        (376 + deposit_txin.txout().max_sat_weight() as u64) * 250,
    );
    // We cannot get a sighash for a non-existing input
    assert_eq!(
        emergency_tx.signature_hash(10, SigHashType::All),
        Err(InputSatisfactionError::OutOfBounds)
    );
    // But for an existing one, all good
    let emergency_tx_sighash_vault = emergency_tx
        .sig_hash(SigHashType::All)
        .expect("Input exists");
    // We can't force it to accept another signature type
    let emer_sighash_all = emergency_tx
        .sig_hash(SigHashType::AllPlusAnyoneCanPay)
        .unwrap();
    let err = satisfy_transaction_input(
        &secp,
        &mut emergency_tx,
        0,
        &emer_sighash_all,
        &stakeholders_priv,
        child_number,
    );
    assert!(err.unwrap_err().to_string().contains("Invalid signature"),);
    // Now, that's the right SIGHASH
    roundtrip!(emergency_tx, EmergencyTransaction);
    satisfy_transaction_input(
        &secp,
        &mut emergency_tx,
        0,
        &emergency_tx_sighash_vault,
        &stakeholders_priv,
        child_number,
    )?;
    roundtrip!(emergency_tx, EmergencyTransaction);
    emergency_tx.finalize(&secp)?;
    roundtrip!(emergency_tx, EmergencyTransaction);

    // Create but don't sign the unvaulting transaction until all revaulting transactions
    // are finalized
    let deposit_txin_sat_cost = deposit_txin.txout().max_sat_weight();
    let mut unvault_tx = UnvaultTransaction::new(
        deposit_txin.clone(),
        &der_unvault_descriptor,
        &der_cpfp_descriptor,
    )?;
    roundtrip!(unvault_tx, UnvaultTransaction);

    assert_eq!(h_unvault, unvault_tx);
    let unvault_value = unvault_tx.psbt().global.unsigned_tx.output[0].value;
    // 548 is the witstrip weight of an unvault tx (1 segwit input, 2 P2WSH txouts), 6 is the
    // feerate is sat/WU, and 30_000 is the CPFP output value.
    assert_eq!(unvault_tx.fees(), (548 + deposit_txin_sat_cost as u64) * 6);

    // Create and sign the cancel transaction
    let rev_unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
    assert_eq!(rev_unvault_txin.txout().txout().value, unvault_value);
    let mut cancel_tx = CancelTransaction::new(
        rev_unvault_txin.clone(),
        &der_deposit_descriptor,
        Amount::from_sat(50),
    )?;
    roundtrip!(cancel_tx, CancelTransaction);
    assert_eq!(h_cancel.feerate_200(), &cancel_tx);
    assert_eq!(
        cancel_tx.deposit_txin(&der_deposit_descriptor).outpoint(),
        OutPoint {
            txid: cancel_tx.txid(),
            vout: 0
        }
    );
    // 376 is the witstrip weight of a cancel tx (1 segwit input, 1 P2WSH txout), 50 is the feerate is sat/WU
    assert_eq!(
        cancel_tx.fees(),
        (376 + rev_unvault_txin.txout().max_sat_weight() as u64) * 50,
    );
    let cancel_tx_sighash = cancel_tx.sig_hash(SigHashType::All).expect("Input exists");
    roundtrip!(cancel_tx, CancelTransaction);
    satisfy_transaction_input(
        &secp,
        &mut cancel_tx,
        0,
        &cancel_tx_sighash,
        &stakeholders_priv,
        child_number,
    )?;
    roundtrip!(cancel_tx, CancelTransaction);
    cancel_tx.finalize(&secp).unwrap();
    roundtrip!(cancel_tx, CancelTransaction);

    let mut unemergency_tx =
        UnvaultEmergencyTransaction::new(rev_unvault_txin.clone(), emergency_address.clone())?;
    roundtrip!(unemergency_tx, UnvaultEmergencyTransaction);
    assert_eq!(h_unemer, unemergency_tx);
    assert_eq!(
        unemergency_tx.emergency_outpoint(),
        OutPoint {
            txid: unemergency_tx.txid(),
            vout: 0
        }
    );

    // 376 is the witstrip weight of an emer tx (1 segwit input, 1 P2WSH txout), 75 is the feerate is sat/WU
    assert_eq!(
        unemergency_tx.fees(),
        (376 + rev_unvault_txin.txout().max_sat_weight() as u64) * 250,
    );
    let unemergency_tx_sighash = unemergency_tx
        .sig_hash(SigHashType::All)
        .expect("Input exists");
    roundtrip!(unemergency_tx, UnvaultEmergencyTransaction);
    satisfy_transaction_input(
        &secp,
        &mut unemergency_tx,
        0,
        &unemergency_tx_sighash,
        &stakeholders_priv,
        child_number,
    )?;
    roundtrip!(unemergency_tx, UnvaultEmergencyTransaction);
    unemergency_tx.finalize(&secp)?;
    roundtrip!(unemergency_tx, UnvaultEmergencyTransaction);

    // Now we can sign the unvault
    let unvault_tx_sighash = unvault_tx.sig_hash(SigHashType::All).expect("Input exists");
    satisfy_transaction_input(
        &secp,
        &mut unvault_tx,
        0,
        &unvault_tx_sighash,
        &stakeholders_priv,
        child_number,
    )?;
    roundtrip!(unvault_tx, UnvaultTransaction);
    unvault_tx.finalize(&secp)?;
    roundtrip!(unvault_tx, UnvaultTransaction);

    // Create a CPFP transaction for the unvault
    // Some fake listunspent outputs
    let listunspent = vec![
        CpfpTxIn::new(
            OutPoint::from_str(
                "f21596dd9df36b86bcf65f0884f1f20675c1fc185bc78a37a9cddb4ae5e3dd9f:0",
            )
            .unwrap(),
            CpfpTxOut::new(Amount::from_sat(30_000), &der_cpfp_descriptor),
        ),
        CpfpTxIn::new(
            OutPoint::from_str(
                "f21596dd9df36b86bcf65f0884f1f20675c1fc185bc78a37a9cddb4ae5e3dd9f:1",
            )
            .unwrap(),
            CpfpTxOut::new(Amount::from_sat(30_000), &der_cpfp_descriptor),
        ),
    ];

    let cpfp_txin = unvault_tx.cpfp_txin(&cpfp_descriptor, &secp).unwrap();
    let cpfp_txins = vec![cpfp_txin.clone(), cpfp_txin];
    let tbc_weight = unvault_tx.max_weight() * 2;
    let tbc_fees = Amount::from_sat(unvault_tx.fees() * 2);
    // Let's ask for a decent feerate
    let added_feerate = 6121;
    // We try to feebump two unvaults in 1 transaction
    let cpfp_tx = CpfpTransaction::from_txins(
        cpfp_txins.clone(),
        tbc_weight,
        tbc_fees,
        added_feerate,
        listunspent.clone(),
    )
    .unwrap();

    // The cpfp tx contains the input of the tx to be cpfped, right?
    assert!(cpfp_tx.tx().input.contains(&cpfp_txins[0].unsigned_txin()));

    assert_eq!(cpfp_tx.tx().output.len(), 1);
    {
        let o = &cpfp_tx.tx().output[0];
        // Either the change is 0 with an OP_RETURN,
        // or its value is bigger than CPFP_MIN_CHANGE, and we send
        // back to the cpfp_txin script_pubkey
        assert!(
            (o.value == 0 && o.script_pubkey.is_op_return())
                || (o.value >= CPFP_MIN_CHANGE
                    && o.script_pubkey == cpfp_txins[0].txout().txout().script_pubkey)
        );
    }

    // we sign the cpfp and then check the package feerate
    let cpfp_fees = cpfp_tx.fees();
    let inputs_len = cpfp_tx.psbt().inputs.len();
    let mut psbt = cpfp_tx.into_psbt();
    for i in 0..inputs_len {
        sign_psbt(&secp, &mut psbt, i, &mancpfp_priv, child_number);
    }
    finalize_psbt(&secp, &mut psbt);
    assert!(
        1000 * (cpfp_fees + unvault_tx.fees())
            / (psbt.global.unsigned_tx.get_weight() as u64 + unvault_tx.max_weight())
            >= unvault_tx.max_feerate() * 1000 + added_feerate
    );

    // Create and sign a spend transaction
    let spend_unvault_txin = unvault_tx.spend_unvault_txin(&der_unvault_descriptor);
    let unvault_value = spend_unvault_txin.txout().txout().value;
    let dummy_txo = TxOut::default();
    let cpfp_value = SpendTransaction::cpfp_txout(
        vec![spend_unvault_txin.clone()],
        vec![SpendTxOut::new(dummy_txo.clone())],
        None,
        &der_cpfp_descriptor,
        0,
    )
    .txout()
    .value;
    let change_value = unvault_value
        .checked_sub(cpfp_value)
        .expect("We would never create such a tx chain (dust)");
    // The overhead incurred to the value of the CPFP output by the change output
    // See https://github.com/revault/practical-revault/blob/master/transactions.md#spend_tx
    const P2WSH_TXO_WEIGHT: u64 = 43 * 4;
    let cpfp_change_overhead = 16 * P2WSH_TXO_WEIGHT;
    let fees = 10_000;
    let (spend_txo, change_txo) = if unvault_value
        > change_value + cpfp_value + cpfp_change_overhead + fees
        && change_value > DEPOSIT_MIN_SATS + fees + cpfp_change_overhead
    {
        (
            TxOut {
                value: unvault_value - cpfp_value - cpfp_change_overhead - change_value - fees,
                ..TxOut::default()
            },
            Some(DepositTxOut::new(
                Amount::from_sat(change_value - cpfp_value - fees),
                &der_deposit_descriptor,
            )),
        )
    } else {
        (
            TxOut {
                value: unvault_value - cpfp_value - fees,
                ..TxOut::default()
            },
            None,
        )
    };
    let mut spend_tx = SpendTransaction::new(
        vec![spend_unvault_txin.clone()],
        vec![SpendTxOut::new(spend_txo.clone())],
        change_txo,
        &der_cpfp_descriptor,
        0,
        true,
    )
    .expect("Amounts ok");
    roundtrip!(spend_tx, SpendTransaction);
    let spend_tx_sighash = spend_tx
        .signature_hash(0, SigHashType::All)
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
        child_number,
    )?;
    roundtrip!(spend_tx, SpendTransaction);
    spend_tx.finalize(&secp)?;
    roundtrip!(spend_tx, SpendTransaction);

    // We can't create a dust output with the Spend
    let dust_txo = TxOut {
        value: 470,
        ..TxOut::default()
    };
    SpendTransaction::new(
        vec![spend_unvault_txin.clone()],
        vec![SpendTxOut::new(dust_txo.clone())],
        None,
        &der_cpfp_descriptor,
        0,
        true,
    )
    .expect_err("Creating a dust output");

    // We can't create a dust change output with the Spend
    SpendTransaction::new(
        vec![spend_unvault_txin],
        vec![],
        Some(DepositTxOut::new(
            Amount::from_sat(329),
            &der_deposit_descriptor,
        )),
        &der_cpfp_descriptor,
        0,
        true,
    )
    .expect_err("Creating a dust output");

    // The spend transaction can also batch multiple unvault txos
    if unvault_spends.len() == 0 {
        return Err(Error::TransactionCreation(
            TransactionCreationError::NegativeFees,
        ));
    }
    let spend_unvault_txins: Vec<UnvaultTxIn> = unvault_spends
        .into_iter()
        .map(|(outpoint, value)| {
            UnvaultTxIn::new(
                outpoint,
                UnvaultTxOut::new(Amount::from_sat(value), &der_unvault_descriptor),
                csv,
            )
        })
        .collect();
    let n_txins = spend_unvault_txins.len();
    let dummy_txo = TxOut::default();
    let cpfp_value = SpendTransaction::cpfp_txout(
        spend_unvault_txins.clone(),
        vec![SpendTxOut::new(dummy_txo.clone())],
        None,
        &der_cpfp_descriptor,
        0,
    )
    .txout()
    .value;
    let fees = 30_000;
    let mut in_value: u64 = 0;
    for txin in spend_unvault_txins.iter() {
        in_value = in_value
            .checked_add(txin.txout().txout().value)
            .ok_or(TransactionCreationError::InsaneAmounts)?;
    }
    let spend_txo = TxOut {
        value: in_value
            .checked_sub(cpfp_value)
            .ok_or(TransactionCreationError::InsaneAmounts)?
            .checked_sub(fees)
            .ok_or(TransactionCreationError::InsaneAmounts)?,
        ..TxOut::default()
    };
    let mut spend_tx = SpendTransaction::new(
        spend_unvault_txins,
        vec![SpendTxOut::new(spend_txo.clone())],
        None,
        &der_cpfp_descriptor,
        0,
        true,
    )?;
    roundtrip!(spend_tx, SpendTransaction);
    assert_eq!(spend_tx.fees(), fees);
    let mut hash_cache = SigHashCache::new(spend_tx.tx());
    let sighashes: Vec<SigHash> = (0..n_txins)
        .into_iter()
        .map(|i| {
            spend_tx
                .signature_hash_cached(i, SigHashType::All, &mut hash_cache)
                .expect("Input exists")
        })
        .collect();
    for (i, spend_tx_sighash) in sighashes.into_iter().enumerate() {
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
            child_number,
        )?
    }

    // Create a CPFP transaction for the (not yet finalized) Spend
    // Some fake listunspent outputs
    let listunspent = vec![
        CpfpTxIn::new(
            OutPoint::from_str(
                "f21596dd9df36b86bcf65f0884f1f20675c1fc185bc78a37a9cddb4ae5e3dd9f:0",
            )
            .unwrap(),
            CpfpTxOut::new(Amount::from_sat(58_000), &der_cpfp_descriptor),
        ),
        CpfpTxIn::new(
            OutPoint::from_str(
                "f21596dd9df36b86bcf65f0884f1f20675c1fc185bc78a37a9cddb4ae5e3dd9f:1",
            )
            .unwrap(),
            CpfpTxOut::new(Amount::from_sat(23_000), &der_cpfp_descriptor),
        ),
    ];

    let cpfp_txin = spend_tx.cpfp_txin(&cpfp_descriptor, &secp).unwrap();
    let cpfp_txins = vec![cpfp_txin.clone()];
    let tbc_weight = spend_tx.max_weight();
    let tbc_fees = Amount::from_sat(spend_tx.fees());
    let added_feerate = 6121;
    let cpfp_tx = CpfpTransaction::from_txins(
        cpfp_txins,
        tbc_weight,
        tbc_fees,
        added_feerate,
        listunspent.clone(),
    )
    .unwrap();

    // The cpfp tx contains the input of the tx to be cpfped
    assert!(cpfp_tx.tx().input.contains(&cpfp_txin.unsigned_txin()));
    assert_eq!(cpfp_tx.tx().output.len(), 1);
    // Either the change is 0 with an OP_RETURN,
    // or its value is bigger than CPFP_MIN_CHANGE, and we send
    // back to the cpfp_txin script_pubkey
    {
        let o = &cpfp_tx.tx().output[0];
        assert!(
            (o.value == 0 && o.script_pubkey.is_op_return())
                || (o.value >= CPFP_MIN_CHANGE
                    && o.script_pubkey == cpfp_txin.txout().txout().script_pubkey)
        );
    }

    // we sign the cpfp and then check the package feerate
    let cpfp_fees = cpfp_tx.fees();
    let inputs_len = cpfp_tx.psbt().inputs.len();
    let mut psbt = cpfp_tx.into_psbt();
    for i in 0..inputs_len {
        sign_psbt(&secp, &mut psbt, i, &mancpfp_priv, child_number);
    }
    finalize_psbt(&secp, &mut psbt);
    assert!(
        1000 * (cpfp_fees + spend_tx.fees())
            / (psbt.global.unsigned_tx.get_weight() as u64 + spend_tx.max_weight())
            >= spend_tx.max_feerate() * 1000 + added_feerate
    );

    roundtrip!(spend_tx, SpendTransaction);
    spend_tx.finalize(&secp)?;
    roundtrip!(spend_tx, SpendTransaction);

    Ok(())
}

pub fn seed_rng(seed: u64) {
    fastrand::seed(seed);
}
