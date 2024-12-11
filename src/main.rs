use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::{Address, KnownHrp, NetworkKind};
use bitcoin::secp256k1::Secp256k1;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::base58;

// electrum Zpub version number https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
const ELECTRUM_ZPUB: [u8; 4] = [2, 170, 126, 211];
// bip32 version number https://en.bitcoin.it/wiki/BIP_0032#Serialization_format
const BTC_XPUB: [u8; 4] = [4, 136, 178, 30];

fn main() {
    // create seed with no password
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "");
    let seed_bytes: &[u8] = seed.as_bytes();
    
    // derive xprv key from seed phrase
    let prvk = Xpriv::new_master(NetworkKind::Main, seed_bytes).unwrap();
    // ESDSA private key
    let private = prvk.to_priv();

    // use private key + secp256k1 to derive ESDSA key and xpub
    let secp = Secp256k1::new();
    let public = private.public_key(&secp);

    let electrum_zpub1 = "Zpub6xYXMPAPepPzktBxjXVCGwzoNDjaoTd2zMFnas6ibyzn5oq5A1TWnFNvV5HhbXB3YANm2YxyY5gYo3XpL1hYP1YGaa5wcMAdYrqiD8a7p8o";
    let electrum_zpub2 = "Zpub6yk2ZNxZ9Grn6zTZbUWcFqkVJDRxNP36LT6pbD57Afdo4Ar6tAtYvUtWV34wqkVkrikBv2tEWef64L3Qm8Xo9fjRur8ZM6QKPZFVbicXZ1R";

    // convert zpubs from electrum Zpub to xpub
    let xpub1 = convert_zpub_to_xpub(&electrum_zpub1);
    let xpub2 = convert_zpub_to_xpub(&electrum_zpub2);

    // sanity check
    assert_eq!(convert_xpub_to_zpub(&xpub1), electrum_zpub1);
    assert_eq!(convert_xpub_to_zpub(&xpub2), electrum_zpub2);

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
    let addr = Address::p2wsh(&scriptbuilder.as_script(), KnownHrp::Mainnet);

    println!("{:?}", addr);
}


// Electrum public keys have thier own versioning system for BIP32 xpub and xprv keys
// https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
// We need to convert to a standard xpub so that the so that we can 
// [0..4] is version number per bip32: https://en.bitcoin.it/wiki/BIP_0032#Serialization_format
fn convert_zpub_to_xpub(zpub: &str) -> Xpub {
    let mut decoded_zpub = base58::decode_check(zpub).unwrap();
    decoded_zpub[0..4].iter_mut()
        .enumerate()
        .for_each(|(i, a)| {
            *a = BTC_XPUB[i];
        });
    let reencoded = base58::encode_check(&decoded_zpub);
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
            *a = ELECTRUM_ZPUB[i];
        });
    let reencoded = base58::encode_check(&decoded_xpub);
    return  reencoded;
}