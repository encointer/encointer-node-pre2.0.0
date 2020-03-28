//  Copyright (c) 2019 Alain Brenzikofer
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

//! an RPC client to encointer node using websockets
//!
//! examples
//! encointer-client 127.0.0.1:9944 transfer //Alice 5G9RtsTbiYJYQYMHbWfyPoeuuxNaCbC16tZ2JGrZ4gRKwz14 1000
//!
#![feature(rustc_private)]

#[macro_use]
extern crate clap;
extern crate log;
extern crate env_logger;

use app_crypto::{ed25519, sr25519};
use keyring::AccountKeyring;
use keystore::Store;
use std::path::PathBuf;
use std::ops::Rem;

use codec::{Decode, Encode};
use primitives::{
    crypto::Ss58Codec,
    hashing::blake2_256,
    sr25519 as sr25519_core, Pair
};
use fixed::traits::LossyInto;
use substrate_api_client::{
    compose_extrinsic, 
    extrinsic::xt_primitives::{GenericAddress, UncheckedExtrinsicV4},
    node_metadata,
    utils::{hexstr_to_u256, hexstr_to_u64, hexstr_to_vec},
    Api,
};

use base58::{FromBase58, ToBase58};
use encointer_ceremonies::{
    Attestation, AttestationIndexType, ClaimOfAttendance,
    CurrencyCeremony, MeetupIndexType, ParticipantIndexType, ProofOfAttendance,
};
use encointer_scheduler::{CeremonyIndexType, CeremonyPhaseType};
use encointer_currencies::{CurrencyIdentifier, Location, Degree};
use encointer_node_runtime::{
    AccountId, Event, Hash, Signature, Moment, ONE_DAY
};

use sr_primitives::traits::{IdentifyAccount, Verify};
//use primitive_types::U256;
use clap::App;
use geojson::GeoJson;
use log::*;
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::sync::mpsc::channel;

type AccountPublic = <Signature as Verify>::Signer;
const KEYSTORE_PATH: &str = "my_keystore";
const PREFUNDING_AMOUNT: u128 = 1_000_000_000;

fn main() {
    env_logger::init();
    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

    let url = matches.value_of("URL").expect("must specify URL");
    info!("connecting to {}", url);
    let api = Api::<sr25519::Pair>::new(format!("ws://{}", url));

    if let Some(_matches) = matches.subcommand_matches("print_metadata") {
        let meta = api.get_metadata();
        println!(
            "Metadata:\n {}",
            node_metadata::pretty_format(&meta).unwrap()
        );
    }

    if let Some(_matches) = matches.subcommand_matches("new_account") {
        // open store without password protection
        let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
        let key: sr25519::AppPair = store.write().generate().unwrap();
        drop(store);
        println!("{}", key.public().to_ss58check())
    }

    if let Some(_matches) = matches.subcommand_matches("new_claim") {
        let account = _matches.value_of("account").unwrap();
        let accountid = get_accountid_from_str(account);
        let cid = get_cid(
            matches
                .value_of("cid")
                .expect("please supply argument --cid"),
        );
        let n_participants = _matches
            .value_of("n_participants")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let claim = new_claim_for(&api, accountid, cid, n_participants);
        println!("{}", hex::encode(claim))
    }

    if let Some(_matches) = matches.subcommand_matches("sign_claim") {
        let signer_arg = _matches.value_of("signer").unwrap();
        info!("first call to get_pair_from_str");
        let claim = ClaimOfAttendance::decode(
            &mut &hex::decode(_matches.value_of("claim").unwrap()).unwrap()[..],
        )
        .unwrap();
        let attestation = sign_claim(claim, signer_arg);
        println!("{}", hex::encode(attestation))
    }

    if let Some(_matches) = matches.subcommand_matches("fund_account") {
        let account = _matches.value_of("account").unwrap();
        let accountid = get_accountid_from_str(account);

        let _api = api.clone().set_signer(AccountKeyring::Alice.pair());
        let xt = _api.balance_transfer(GenericAddress::from(accountid.clone()), PREFUNDING_AMOUNT);
        info!(
            "[+] Alice is generous and pre funds account {}\n",
            accountid.to_ss58check()
        );
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        info!(
            "[+] Pre-Funding transaction got finalized. Hash: {:?}\n",
            tx_hash
        );
        let result = _api.get_free_balance(&accountid.clone());
        println!("balance for {} is now {}", accountid.to_ss58check(), result);
    }

    if let Some(_matches) = matches.subcommand_matches("list_accounts") {
        let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
        println!("sr25519 keys:");
        for pubkey in store
            .read()
            .public_keys::<sr25519::AppPublic>()
            .unwrap()
            .into_iter()
        {
            println!("{}", pubkey.to_ss58check());
        }
        println!("ed25519 keys:");
        for pubkey in store
            .read()
            .public_keys::<ed25519::AppPublic>()
            .unwrap()
            .into_iter()
        {
            println!("{}", pubkey.to_ss58check());
        }
        drop(store);
    }

    if let Some(_matches) = matches.subcommand_matches("listen") {
        info!("Subscribing to events");
        let (events_in, events_out) = channel();
        api.subscribe_events(events_in.clone());
        loop {
            let event_str = events_out.recv().unwrap();
            let _unhex = hexstr_to_vec(event_str).unwrap();
            let mut _er_enc = _unhex.as_slice();
            let _events = Vec::<system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
            match _events {
                Ok(evts) => {
                    for evr in &evts {
                        debug!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
                        match &evr.event {
                            /*                            Event::balances(be) => {
                                println!(">>>>>>>>>> balances event: {:?}", be);
                                match &be {
                                    balances::RawEvent::Transfer(transactor, dest, value, fee) => {
                                        println!("Transactor: {:?}", transactor);
                                        println!("Destination: {:?}", dest);
                                        println!("Value: {:?}", value);
                                        println!("Fee: {:?}", fee);
                                    }
                                    _ => {
                                        debug!("ignoring unsupported balances event");
                                    }
                                }
                            },*/
                            Event::encointer_ceremonies(ee) => {
                                println!(">>>>>>>>>> ceremony event: {:?}", ee);
                                match &ee {
                                    encointer_ceremonies::RawEvent::ParticipantRegistered(
                                        accountid,
                                    ) => {
                                        println!(
                                            "Participant registered for ceremony: {:?}",
                                            accountid
                                        );
                                    }
                                }
                            }, 
                            Event::encointer_scheduler(ee) => {
                                println!(">>>>>>>>>> scheduler event: {:?}", ee);
                                match &ee {
                                    encointer_scheduler::Event::PhaseChangedTo(phase) => {
                                        println!("Phase changed to: {:?}", phase);
                                    }
                                }
                            }
                            Event::encointer_currencies(ee) => {
                                println!(">>>>>>>>>> currency event: {:?}", ee);
                                match &ee {
                                    encointer_currencies::RawEvent::CurrencyRegistered(account, cid) => {
                                        println!("Currency registered: by {}, cid: {:?}", account, cid);
                                    }
                                }
                            },
                            _ => debug!("ignoring unsupported module event: {:?}", evr.event),
                        }
                    }
                }
                Err(_) => error!("couldn't decode event record list"),
            }
        }
    }

    if let Some(_matches) = matches.subcommand_matches("get_balance") {
        let account = _matches.value_of("account").unwrap();
        let accountid = get_accountid_from_str(account);
        let balance = match matches.value_of("cid") {
            Some(cid_str) => {
                let cid = get_cid(cid_str);
                let result_str = api
                    .get_storage_double_map("EncointerBalances", "Balance", cid.encode(), accountid.encode())
                    .unwrap();
                hexstr_to_u256(result_str).unwrap()
            }
            None => {
                let result_str = api
                    .get_storage("Balances", "FreeBalance", Some(accountid.encode()))
                    .unwrap();
                hexstr_to_u256(result_str).unwrap()
            }
        };
        info!("ss58 is {}", accountid.to_ss58check());
        println!("balance for {} is {}", account, balance);
    }

    if let Some(_matches) = matches.subcommand_matches("get_phase") {
        let phase = get_current_phase(&api);
        println!("{:?}", phase);
    }

    if let Some(_matches) = matches.subcommand_matches("transfer") {
        let arg_from = _matches.value_of("from").unwrap();
        let arg_to = _matches.value_of("to").unwrap();
        let amount = u128::from_str_radix(_matches.value_of("amount").unwrap(), 10)
            .expect("amount can be converted to u128");
        let from = get_pair_from_str(arg_from);
        let to = get_accountid_from_str(arg_to);
        info!("from ss58 is {}", from.public().to_ss58check());
        info!("to ss58 is {}", to.to_ss58check());
        let _api = api.clone().set_signer(sr25519_core::Pair::from(from));
        let xt = _api.balance_transfer(GenericAddress::from(to.clone()), amount);
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);
        let result = _api.get_free_balance(&to);
        println!("balance for {} is now {}", to, result);
    }

    if let Some(_matches) = matches.subcommand_matches("next_phase") {
        let _api = api.clone().set_signer(AccountKeyring::Alice.pair());

        let xt: UncheckedExtrinsicV4<_> =
            compose_extrinsic!(_api.clone(), "EncointerScheduler", "next_phase");

        // send and watch extrinsic until finalized
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        let phase = get_current_phase(&api);
        println!(
            "Transaction got finalized. Phase is now: {:?}. tx hash: {:?}",
            phase, tx_hash
        );
    }

    if let Some(_matches) = matches.subcommand_matches("grant_reputation") {
        // root call, must be signed by master
        let _api = api.clone().set_signer(AccountKeyring::Alice.pair());
        let p_arg = _matches.value_of("account").unwrap();
        let accountid = get_accountid_from_str(p_arg);
        let cid = get_cid(
            matches
                .value_of("cid")
                .expect("please supply argument --cid"),
        );

        let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
            _api.clone(),
            "EncointerCeremonies",
            "grant_reputation",
            cid,
            accountid.clone()
        );

        // send and watch extrinsic until finalized
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        println!(
            "Transaction got finalized. Account: {} should now have reputation. txhash: {:?}",
            accountid.to_ss58check(),
            tx_hash
        );
    }

    if let Some(_matches) = matches.subcommand_matches("register_participant") {
        let p_arg = _matches.value_of("account").unwrap();
        let accountid = get_accountid_from_str(p_arg);
        let p = get_pair_from_str(p_arg);
        let cindex = get_ceremony_index(&api);
        let cid = get_cid(
            matches
                .value_of("cid")
                .expect("please supply argument --cid"),
        );
        // FIXME:
        let proof = if _matches.is_present("proof") {
            Some(prove_attendance(accountid, cid, cindex - 1, p_arg))
        } else {
            None
        };
        //let proof : Option<ProofOfAttendance<Signature, AccountId>> = None;
        // assume users keep the same pair forever (so prover == attendee)
        //let proof = prove_attendance(acountid, cid, cindex-1)

        info!("ss58 is {}", p.public().to_ss58check());
        if get_current_phase(&api) != CeremonyPhaseType::REGISTERING {
            println!("wrong ceremony phase for registering participant");
            return;
        }
        let _api = api.clone().set_signer(sr25519_core::Pair::from(p.clone()));
        let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
            _api.clone(),
            "EncointerCeremonies",
            "register_participant",
            cid,
            proof
        );

        // send and watch extrinsic until finalized
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        info!("Transaction got finalized. tx hash: {:?}", tx_hash);
        println!("registration finalized: {}", p.public().to_ss58check());
    }

    if let Some(_matches) = matches.subcommand_matches("register_attestations") {
        let p_arg = _matches.value_of("account").unwrap();
        let signer = get_pair_from_str(p_arg);

        if get_current_phase(&api) != CeremonyPhaseType::ATTESTING {
            println!("wrong ceremony phase for registering participant");
            return;
        }
        let attestation_args: Vec<_> = _matches.values_of("attestation").unwrap().collect();
        let mut attestations: Vec<Attestation<Signature, AccountId, Moment>> = vec![];
        for arg in attestation_args.iter() {
            let w = Attestation::decode(&mut &hex::decode(arg).unwrap()[..]).unwrap();
            attestations.push(w);
        }

        let _api = api.clone().set_signer(sr25519_core::Pair::from(signer));
        let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
            _api.clone(),
            "EncointerCeremonies",
            "register_attestations",
            attestations.clone()
        );
        // send and watch extrinsic until finalized
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        println!("Transaction got finalized. tx hash: {:?}", tx_hash);
    }

    if let Some(_matches) = matches.subcommand_matches("list_meetup_registry") {
        let cindex = get_ceremony_index(&api);
        let cid = get_cid(
            matches
                .value_of("cid")
                .expect("please supply argument --cid"),
        );
        println!(
            "listing meetups for cid {} and ceremony nr {}",
            cid.encode().to_base58(),
            cindex
        );
        let mcount = get_meetup_count(&api, (cid, cindex));
        println!("number of meetups assigned:  {}", mcount);
        for m in 1..=mcount {
            println!("MeetupRegistry[{}, {}] location is {:?}", 
                cindex, m, get_meetup_location(&api, cid, m));
            println!("MeetupRegistry[{}, {}] meeting time is {:?}", 
                cindex, m, get_meetup_time(&api, cid, m));
            match get_meetup_participants(&api, (cid, cindex), m) {
                Some(participants) => {
                    println!("MeetupRegistry[{}, {}]participants are:", cindex, m);
                    for p in participants.iter() {
                        println!("   {:?}", p);
                    }
                }
                None => println!("MeetupRegistry[{}, {}] EMPTY", cindex, m),
            }
        }
    }

    if let Some(_matches) = matches.subcommand_matches("list_participant_registry") {
        let cindex = get_ceremony_index(&api);
        let cid = get_cid(
            matches
                .value_of("cid")
                .expect("please supply argument --cid"),
        );
        println!(
            "listing participants for cid {} and ceremony nr {}",
            cid.encode().to_base58(),
            cindex
        );
        let pcount = get_participant_count(&api, (cid, cindex));
        println!("number of participants assigned:  {}", pcount);
        for p in 1..pcount + 1 {
            let accountid = get_participant(&api, (cid, cindex), p).unwrap();
            println!("ParticipantRegistry[{}, {}] = {:?}", cindex, p, accountid);
        }
    }

    if let Some(_matches) = matches.subcommand_matches("list_currencies") {
        let cids = get_currency_identifiers(&api).expect("no currency registered");
        println!("number of currencies:  {}", cids.len());
        for cid in cids.iter() {
            println!("currency with cid {}", cid.encode().to_base58());
        }
    }

    if let Some(_matches) = matches.subcommand_matches("list_attestations_registry") {
        let cindex = get_ceremony_index(&api);
        let cid = get_cid(
            matches
                .value_of("cid")
                .expect("please supply argument --cid"),
        );
        println!(
            "listing attestations for cid {} and ceremony nr {}",
            cid.encode().to_base58(),
            cindex
        );
        let wcount = get_attestation_count(&api, (cid, cindex));
        println!("number of attestations:  {}", wcount);
        let pcount = get_participant_count(&api, (cid, cindex));

        let mut participants_windex = HashMap::new();
        for p in 1..pcount + 1 {
            let accountid =
                get_participant(&api, (cid, cindex), p).expect("error getting participant");
            match get_participant_attestation_index(&api, (cid, cindex), &accountid) {
                Some(windex) => {
                    participants_windex.insert(windex as AttestationIndexType, accountid)
                }
                _ => continue,
            };
        }
        for w in 1..wcount + 1 {
            let attestations = get_attestations(&api, (cid, cindex), w);
            println!(
                "AttestationRegistry[{}, {} ({})] = {:?}",
                cindex, w, participants_windex[&w], attestations
            );
        }
    }

    if let Some(_matches) = matches.subcommand_matches("new_currency") {
        let p_arg = _matches.value_of("signer").unwrap();
        let signer = get_pair_from_str(p_arg);

        let spec_file = _matches.value_of("specfile").unwrap();

        let spec_str = fs::read_to_string(spec_file).unwrap();
        let geoloc = spec_str.parse::<GeoJson>().unwrap();

        let mut loc = Vec::with_capacity(100);
        match geoloc {
            GeoJson::FeatureCollection(ref ctn) => {
                for feature in &ctn.features {
                    let val = &feature.geometry.as_ref().unwrap().value;
                    if let geojson::Value::Point(pt) = val {
                        let l = Location {
                            lon: Degree::from_num(pt[0]),
                            lat: Degree::from_num(pt[1]),
                        };
                        loc.push(l);
                        debug!("lon: {} lat {} => {:?}", pt[0], pt[1], l);
                    }
                }
            }
            _ => (),
        };
        let meta: serde_json::Value = serde_json::from_str(&spec_str).unwrap();
        debug!("meta: {:?}", meta["currency_meta"]);
        let bootstrappers: Vec<AccountId> = meta["currency_meta"]["bootstrappers"]
            .as_array()
            .expect("bootstrappers must be array")
            .iter()
            .map(|a| get_accountid_from_str(&a.as_str().unwrap()))
            .collect();

        let cid = blake2_256(&(loc.clone(), bootstrappers.clone()).encode());
        let name = meta["currency_meta"]["name"].as_str().unwrap();
        info!("bootstrappers: {:?}", bootstrappers);
        info!("name: {}", name);
        info!("Currency registered by {}", signer.public().to_ss58check());

        let _api = api.clone().set_signer(sr25519_core::Pair::from(signer));
        let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
            _api.clone(),
            "EncointerCurrencies",
            "new_currency",
            loc,
            bootstrappers
        );
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        info!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);
        println!("{}", cid.to_base58())
    }
}

fn get_cid(cid: &str) -> CurrencyIdentifier {
    CurrencyIdentifier::decode(&mut &cid.from_base58().unwrap()[..]).unwrap()
}

fn get_accountid_from_str(account: &str) -> AccountId {
    info!("getting AccountId from -{}-", account);
    match &account[..2] {
        "//" => AccountPublic::from(sr25519::Pair::from_string(account, None).unwrap().public())
            .into_account(),
        _ => AccountPublic::from(sr25519::Public::from_ss58check(account).unwrap()).into_account(),
    }
}

// get a pair either form keyring (well known keys) or from the store
fn get_pair_from_str(account: &str) -> sr25519::AppPair {
    info!("getting pair for {}", account);
    match &account[..2] {
        "//" => sr25519::AppPair::from_string(account, None).unwrap(),
        _ => {
            info!("fetching from keystore at {}", &KEYSTORE_PATH);
            // open store without password protection
            let store =
                Store::open(PathBuf::from(&KEYSTORE_PATH), None).expect("store should exist");
            info!("store opened");
            let _pair = store
                .read()
                .key_pair::<sr25519::AppPair>(
                    &sr25519::Public::from_ss58check(account).unwrap().into(),
                )
                .unwrap();
            drop(store);
            _pair
        }
    }
}

fn get_ceremony_index(api: &Api<sr25519::Pair>) -> CeremonyIndexType {
    hexstr_to_u64(
        api.get_storage("EncointerScheduler", "CurrentCeremonyIndex", None)
            .unwrap(),
    )
    .unwrap() as CeremonyIndexType
}

fn get_current_phase(api: &Api<sr25519::Pair>) -> CeremonyPhaseType {
    let result_str = api
        .get_storage("EncointerScheduler", "CurrentPhase", None)
        .unwrap();
    CeremonyPhaseType::decode(&mut &hexstr_to_vec(result_str).unwrap()[..]).unwrap()
}

fn get_meetup_count(api: &Api<sr25519::Pair>, key: CurrencyCeremony) -> MeetupIndexType {
    hexstr_to_u64(
        api.get_storage("EncointerCeremonies", "MeetupCount", Some(key.encode()))
            .unwrap(),
    )
    .unwrap() as MeetupIndexType
}

fn get_participant_count(api: &Api<sr25519::Pair>, key: CurrencyCeremony) -> ParticipantIndexType {
    hexstr_to_u64(
        api.get_storage(
            "EncointerCeremonies",
            "ParticipantCount",
            Some(key.encode()),
        )
        .unwrap(),
    )
    .unwrap() as ParticipantIndexType
}

fn get_attestation_count(api: &Api<sr25519::Pair>, key: CurrencyCeremony) -> ParticipantIndexType {
    hexstr_to_u64(
        api.get_storage(
            "EncointerCeremonies",
            "AttestationCount",
            Some(key.encode()),
        )
        .unwrap(),
    )
    .unwrap() as ParticipantIndexType
}

fn get_participant(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    pindex: ParticipantIndexType,
) -> Option<AccountId> {
    let res = api
        .get_storage_double_map(
            "EncointerCeremonies",
            "ParticipantRegistry",
            key.encode(),
            pindex.encode(),
        )
        .unwrap();
    match res.as_str() {
        "null" => None,
        _ => {
            let accountid: AccountId =
                Decode::decode(&mut &hexstr_to_vec(res).unwrap()[..]).unwrap();
            Some(accountid)
        }
    }
}

fn get_meetup_index_for(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    account: &AccountId,
) -> Option<MeetupIndexType> {
    let res = hexstr_to_u64(
        api.get_storage_double_map(
            "EncointerCeremonies",
            "MeetupIndex",
            key.encode(),
            (*account).encode(),
        )
        .unwrap(),
    )
    .unwrap();
    info!(
        "got meetup index for {}: {}",
        (*account).to_ss58check(),
        res
    );
    Some(res)
}

fn get_meetup_participants(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    mindex: MeetupIndexType,
) -> Option<Vec<AccountId>> {
    let res = api
        .get_storage_double_map(
            "EncointerCeremonies",
            "MeetupRegistry",
            key.encode(),
            mindex.encode(),
        )
        .unwrap();
    match res.as_str() {
        "null" => None,
        _ => {
            let participants: Vec<AccountId> =
                Decode::decode(&mut &hexstr_to_vec(res).unwrap()[..]).unwrap();
            Some(participants)
        }
    }
}

fn get_attestations(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    windex: ParticipantIndexType,
) -> Option<Vec<AccountId>> {
    let res = api
        .get_storage_double_map(
            "EncointerCeremonies",
            "AttestationRegistry",
            key.encode(),
            windex.encode(),
        )
        .unwrap();
    match res.as_str() {
        "null" => None,
        _ => {
            let attestations: Vec<AccountId> =
                Decode::decode(&mut &hexstr_to_vec(res).unwrap()[..]).unwrap();
            Some(attestations)
        }
    }
}

fn get_participant_attestation_index(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    accountid: &AccountId,
) -> Option<ParticipantIndexType> {
    let res = api
        .get_storage_double_map(
            "EncointerCeremonies",
            "AttestationIndex",
            key.encode(),
            accountid.encode(),
        )
        .unwrap();
    match res.as_str() {
        "null" => None,
        _ => match hexstr_to_u64(res) {
            Ok(windex) => Some(windex as ParticipantIndexType),
            _ => None,
        },
    }
}

fn new_claim_for(
    api: &Api<sr25519::Pair>,
    accountid: AccountId,
    cid: CurrencyIdentifier,
    n_participants: u32,
) -> Vec<u8> {
    let cindex = get_ceremony_index(api);
    let mindex = get_meetup_index_for(api, (cid, cindex), &accountid).unwrap();

    // implicitly assume that participant meet at the right place at the right time
    let mloc = get_meetup_location(api, cid, mindex).unwrap();
    let mtime = get_meetup_time(api, cid, mindex).unwrap();

    let claim = ClaimOfAttendance::<AccountId, Moment> {
        claimant_public: accountid,
        currency_identifier: cid,
        ceremony_index: cindex,
        meetup_index: mindex,
        location: mloc,
        timestamp: mtime,
        number_of_participants_confirmed: n_participants,
    };
    claim.encode()
}

fn sign_claim(claim: ClaimOfAttendance<AccountId, Moment>, account_str: &str) -> Vec<u8> {
    info!("second call to get_pair_from_str");
    let pair = get_pair_from_str(account_str);
    let accountid = get_accountid_from_str(account_str);
    let attestation = Attestation {
        claim: claim.clone(),
        signature: Signature::from(sr25519_core::Signature::from(pair.sign(&claim.encode()))),
        public: accountid,
    };
    attestation.encode()
}

fn get_currency_identifiers(api: &Api<sr25519::Pair>) -> Option<Vec<CurrencyIdentifier>> {
    let res = api
        .get_storage("EncointerCurrencies", "CurrencyIdentifiers", None)
        .unwrap();
    match res.as_str() {
        "null" => None,
        _ => {
            let cids: Vec<CurrencyIdentifier> =
                Decode::decode(&mut &hexstr_to_vec(res).unwrap()[..]).unwrap();
            Some(cids)
        }
    }
}

fn get_currency_locations(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier) -> Vec<Location> {
    Decode::decode(&mut &hexstr_to_vec(
        api.get_storage(
            "EncointerCurrencies",
            "Locations",
            Some(cid.encode())
        )
        .unwrap()).unwrap()[..]).unwrap()
}

fn get_meetup_location(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier, mindex: MeetupIndexType) -> Option<Location> {
    let locations = get_currency_locations(api, cid);
    let lidx = (mindex -1) as usize;
    if lidx >= locations.len() {
        return None 
    } 
    Some(locations[lidx])
}

fn get_meetup_time(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier, mindex: MeetupIndexType) -> Option<Moment> {
    let mlocation = get_meetup_location(api, cid, mindex).unwrap();
    let mlon: f64 = mlocation.lon.lossy_into();
    let cindex = get_ceremony_index(&api);

    let next_phase_timestamp = hexstr_to_u64(api.get_storage(
        "EncointerScheduler",
        "NextPhaseTimestamp",
        None
    ).unwrap()).unwrap();

    let attesting_start = match get_current_phase(api) {
        CeremonyPhaseType::ASSIGNING => next_phase_timestamp - next_phase_timestamp.rem(ONE_DAY),
        CeremonyPhaseType::ATTESTING => {
            let attesting_duration = hexstr_to_u64(api.get_storage(
                "EncointerScheduler",
                "PhaseDurations",
                Some(CeremonyPhaseType::ATTESTING.encode()),
            ).unwrap()).unwrap();
            next_phase_timestamp - attesting_duration - next_phase_timestamp.rem(ONE_DAY)
        },
        CeremonyPhaseType::REGISTERING => panic!("ceremony phase must be ASSIGNING or ATTESTING to request meetup location.")
    };
    
    // next phase is ATTESTING
    Some(attesting_start + ONE_DAY
    - (mlon / 360.0 * ONE_DAY as f64) as Moment )
}

fn prove_attendance(
    prover: AccountId,
    cid: CurrencyIdentifier,
    cindex: CeremonyIndexType,
    attendee_str: &str,
) -> ProofOfAttendance<Signature, AccountId> {
    let msg = (prover.clone(), cindex);
    let attendee = get_pair_from_str(attendee_str);
    let attendeeid = get_accountid_from_str(attendee_str);
    ProofOfAttendance {
        prover_public: prover,
        currency_identifier: cid,
        ceremony_index: cindex,
        attendee_public: attendeeid,
        attendee_signature: Signature::from(sr25519_core::Signature::from(
            attendee.sign(&msg.encode()),
        )),
    }
}
