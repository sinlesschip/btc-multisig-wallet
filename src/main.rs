use std::str::FromStr;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::{Address, KnownHrp, NetworkKind};
use bitcoin::secp256k1::Secp256k1;
use bip39::{Mnemonic, Language, Seed};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::base58;


// electrum Zpub version number https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
const ELECTRUM_ZPUB: [u8; 4] = [2, 170, 126, 211];

// bip32 version number https://en.bitcoin.it/wiki/BIP_0032#Serialization_format
const BTC_XPUB: [u8; 4] = [4, 136, 178, 30];
const TEST_NET_XPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

// electrum testnet version number
const ELECTRUM_VPUB: [u8; 4] = [0x02, 0x57, 0x54, 0x83];

const NETWORK: NetworkKind = NetworkKind::Test;
const HRP: KnownHrp = KnownHrp::Testnets;

fn main() {
    // create seed with no password
    let mnemonic = Mnemonic::from_phrase("input sound grid grit shiver certain public notice useless supreme friend spend", Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");
    let seed_bytes = seed.as_bytes();
    let prvk = Xpriv::new_master(NETWORK, seed_bytes).unwrap();

    let secp = Secp256k1::new();

    // use m/1h path, to match electrum
    let path = DerivationPath::master();
    let path = path.into_child(bitcoin::bip32::ChildNumber::Hardened { index: 1 });
    let pkey_child = prvk.derive_priv(&secp, &path).unwrap();

    let electrum_zpub1 = "Vpub5fDU8iUj46E5MhRVQ6LhSbcngM9o2yf3KuAuTHXB5xVFsQaA9NoGHzkNQFTMbtZMubuY2eajhSGMFu5ZTE3VC4os7DJFGhtgTxb8erdF3uG";
    let electrum_zpub2 = "Vpub5gQyLiGtYYgrhoh6G3N7RVNUcLrAbu56g11wTdVZee8GqmbBsYEJSEFxQDEbr7t5EAGxv8Vzg1EtXBb9tLsjxj12SVLs1T8NJezv3NiWkVe";

    let xpub: Xpub = Xpub::from_priv(&secp, &pkey_child);
    // convert electrums encoding to standard bip32
    let xpub1: Xpub = str_to_xpub(&electrum_zpub1);
    let xpub2: Xpub = str_to_xpub(&electrum_zpub2);

    // sanity check
    assert_eq!(convert_xpub_to_zpub(&xpub1), electrum_zpub1);
    assert_eq!(convert_xpub_to_zpub(&xpub2), electrum_zpub2);

    // generate m/1'/0/0 for each xpub
    let pp = DerivationPath::from_str("m/0/0").unwrap();
    let xpub = xpub.derive_pub(&secp, &pp).unwrap();
    let xpub1 = xpub1.derive_pub(&secp, &pp).unwrap();
    let xpub2 = xpub2.derive_pub(&secp, &pp).unwrap();
   
    // need to be sorted for script
    let mut pubs = vec![xpub.to_pub(),
                        xpub1.to_pub(), 
                        xpub2.to_pub()
                        ];
    pubs.sort();
   

    // create p2sh script
    // 2 <PubKey1> <PubKey2> <PubKey3> 3 OP_CHECKMULTISIG
    let mut scriptbuilder = Builder::new();
    scriptbuilder = scriptbuilder.push_int(2)
                .push_key(&bitcoin::PublicKey::from(pubs[0]))
                .push_key(&bitcoin::PublicKey::from(pubs[1]))
                .push_key(&bitcoin::PublicKey::from(pubs[2]))
                .push_int(3)
                .push_opcode(opcodes::all::OP_CHECKMULTISIG);



    // bech32 encoded multisig address
    let addr = Address::p2wsh(&scriptbuilder.as_script(), HRP);

    println!("{:?}", addr);

}


// Electrum public keys have thier own versioning system for xpub and xprv keys
// https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
// We need to convert to a standard xpub so that the so that we can use it in the p2wsh script
// [0..4] is version number per bip32: https://en.bitcoin.it/wiki/BIP_0032#Serialization_format
// can be used on any electrum pub key
fn str_to_xpub(pubk: &str) -> Xpub {
    let mut decoded_pubk = base58::decode_check(pubk).unwrap();
    decoded_pubk[0..4].iter_mut()
        .enumerate()
        .for_each(|(i, a)| {
            *a = TEST_NET_XPUB[i];
        });
    let data = decoded_pubk;
    let xpub = Xpub {
        network: NETWORK,
        depth: data[4],
        parent_fingerprint: data[5..9]
            .try_into()
            .expect("9 - 5 == 4, which is the Fingerprint length"),
        child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
        chain_code: data[13..45]
            .try_into()
            .expect("45 - 13 == 32, which is the ChainCode length"),
        public_key: bitcoin::secp256k1::PublicKey::from_slice(&data[45..78]).unwrap(),
    };
    xpub
}

fn convert_xpub_to_zpub(xpub: &Xpub) -> String {
    let mut decoded_xpub = base58::decode_check(xpub.to_string().as_str()).unwrap();
    decoded_xpub[0..4].iter_mut()
        .enumerate()
        .for_each(|(i, a)| {
            *a = ELECTRUM_VPUB[i];
        });
    let reencoded = base58::encode_check(&decoded_xpub);
    
    return  reencoded;
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELECTRUM_ZPUB: &str = "Vpub5fDU8iUj46E5MhRVQ6LhSbcngM9o2yf3KuAuTHXB5xVFsQaA9NoGHzkNQFTMbtZMubuY2eajhSGMFu5ZTE3VC4os7DJFGhtgTxb8erdF3uG";

    #[test]
    fn conversion_from_string_to_xpub() {
        let result: Xpub = str_to_xpub(ELECTRUM_ZPUB);
        assert_eq!(convert_xpub_to_zpub(&result), ELECTRUM_ZPUB);

    }

}
