use std::str::FromStr;

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::{witness_program, Address, KnownHrp, NetworkKind, PrivateKey, PublicKey, WitnessProgram};
use bitcoin::secp256k1::Secp256k1;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::base58;
use bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use hex as hhex;


// electrum Zpub version number https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
const ELECTRUM_ZPUB: [u8; 4] = [2, 170, 126, 211];
// bip32 version number https://en.bitcoin.it/wiki/BIP_0032#Serialization_format
const BTC_XPUB: [u8; 4] = [4, 136, 178, 30];
const ELECTRUM_YPUB: [u8; 4] = [2, 87, 84, 131];
const NETWORK: NetworkKind = NetworkKind::Test;
const HRP: KnownHrp = KnownHrp::Testnets;

fn main() {
    // create seed with no password
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "");
    let seed_bytes: &[u8] = seed.as_bytes();
    let mnemonic = "abstract accuse actress inside ribbon slide slight speak stem surge tattoo trouble";

    // generate electum seed
    let electrum_seed = generate_seed_with_version(mnemonic.to_string().as_str(), "100").unwrap();
    let e_seed_bytes = electrum_seed.0.as_bytes();
    println!("{:?}", electrum_seed);
    
    // derive xprv key from seed phrase
  

    let prvk = Xpriv::new_master(NETWORK, e_seed_bytes).unwrap();
    let doo = bitcoin::secp256k1::SecretKey::from_slice(&e_seed_bytes[..32]).unwrap();

    let xpriv = Xpriv {
        network: NETWORK.into(),
        depth: 0,
        parent_fingerprint: Default::default(), 
        child_number: ChildNumber::from_normal_idx(0).unwrap(),
        private_key: doo,
        chain_code: ChainCode::from(&doo.secret_bytes())
    };
    println!("{}", xpriv);

    let secp = Secp256k1::new();

    // use m/1h path 
    let path = DerivationPath::master();
    let path = path.into_child(bitcoin::bip32::ChildNumber::Hardened { index: 1 });
    let pkey_child = prvk.derive_priv(&secp, &path).unwrap();
    println!("{}", convert_xpub_to_zpub(&Xpub::from_priv(&secp, &pkey_child)));

    let public_path = DerivationPath::master().child(bitcoin::bip32::ChildNumber::Normal { index: (0) }).child(bitcoin::bip32::ChildNumber::Normal { index: (0) });
    let xpub = Xpub::from_priv(&secp, &prvk);
    // let xpub = xpub.derive_pub(&secp, &path).unwrap();
    // let public = PublicKey::new(xpub);

    let electrum_zpub1 = "Vpub5fDU8iUj46E5MhRVQ6LhSbcngM9o2yf3KuAuTHXB5xVFsQaA9NoGHzkNQFTMbtZMubuY2eajhSGMFu5ZTE3VC4os7DJFGhtgTxb8erdF3uG";
    let electrum_zpub2 = "Vpub5gQyLiGtYYgrhoh6G3N7RVNUcLrAbu56g11wTdVZee8GqmbBsYEJSEFxQDEbr7t5EAGxv8Vzg1EtXBb9tLsjxj12SVLs1T8NJezv3NiWkVe";

    // convert zpubs from electrum to xpub
    let xpub1: Xpub = str_to_xpub(&electrum_zpub1);
    let xpub2: Xpub = str_to_xpub(&electrum_zpub2);

    // sanity check
    assert_eq!(convert_xpub_to_zpub(&xpub1), electrum_zpub1);
    assert_eq!(convert_xpub_to_zpub(&xpub2), electrum_zpub2);

    
    let pkey_child = prvk.derive_priv(&secp, &public_path).unwrap();
    let private = pkey_child.to_priv();
    let public = private.public_key(&secp);
    println!("{}", public_path);


    // create p2sh script
    // 2 <PubKey1> <PubKey2> <PubKey3> 3 OP_CHECKMULTISIG
    let mut scriptbuilder = Builder::new();
    scriptbuilder = scriptbuilder.push_int(2)
                .push_key(&public)
                .push_key(&bitcoin::PublicKey::from(xpub1.to_pub()))
                .push_key(&bitcoin::PublicKey::from(xpub2.to_pub()))
                .push_int(3)
                .push_opcode(opcodes::all::OP_CHECKMULTISIG);



    // bech32 encoded multisig address
    let addr = Address::p2wsh(&scriptbuilder.as_script(), HRP);
    let addr2 = bitcoin::bech32::segwit::encode_v1(bitcoin::bech32::hrp::TB, WitnessProgram::p2wsh(&scriptbuilder.as_script()).program().as_bytes());



    println!("{:?}", addr);
    println!("{:?}", addr2);

}


// Electrum public keys have thier own versioning system for BIP32 xpub and xprv keys
// https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
// We need to convert to a standard xpub so that the so that we can use it in the p2wsh script
// [0..4] is version number per bip32: https://en.bitcoin.it/wiki/BIP_0032#Serialization_format
// can be used on any electrum pub key
fn str_to_xpub(pubk: &str) -> Xpub {
    let mut decoded_pubk = base58::decode_check(pubk).unwrap();
    decoded_pubk[0..4].iter_mut()
        .enumerate()
        .for_each(|(i, a)| {
            *a = BTC_XPUB[i];
        });
    let reencoded = base58::encode_check(&decoded_pubk);
    match reencoded.parse::<Xpub>() {
        Ok(xpub) => return xpub,
        Err(err) => panic!("{}", err)
    };
}

fn convert_xpub_to_zpub(xpub: &Xpub) -> String {
    let mut decoded_xpub = base58::decode_check(xpub.to_string().as_str()).unwrap();
    decoded_xpub[0..4].iter_mut()
        .enumerate()
        .for_each(|(i, a)| {
            *a = ELECTRUM_YPUB[i];
        });
    let reencoded = base58::encode_check(&decoded_xpub);
    return  reencoded;
}

// https://electrum.readthedocs.io/en/latest/seedphrase.html#version-number
fn generate_seed_with_version(seed_phrase: &str, version_prefix: &str) -> Result<(String, u64), Box<dyn std::error::Error>> {
    let mut nonce = 0;

    loop {
        // Normalize the seed phrase with the nonce appended
        let normalized = format!("{} {}", seed_phrase, nonce);

        // Compute HMAC-SHA512 hash
        let mut mac: HmacEngine<sha512::Hash> = HmacEngine::new(b"Seed version");
        mac.input(normalized.as_bytes());
        let result = Hmac::from_engine(mac);
        let bytes = result.as_byte_array();
        
        
        // Encode the hash to hexadecimal
        let hex_string = hhex::encode(bytes);
        // Check if the hash starts with the desired prefix
        if hex_string.starts_with(version_prefix) {
            return Ok((hex_string, nonce));
        }

        // Increment the nonce for the next iteration
        nonce += 1;
    }
}