use super::*;
use ckb_auth_rs::{AuthAlgorithmIdType, CkbAuthType, EntryCategoryType};
use ckb_testtool::{
    ckb_crypto::secp::{Generator, Privkey},
    ckb_hash::{blake2b_256, new_blake2b},
    ckb_types::{
        bytes::{BufMut, Bytes, BytesMut},
        core::{Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView},
        packed::{CellDep, CellInputBuilder, CellOutput, WitnessArgs, WitnessArgsBuilder},
        prelude::*,
        H256,
    },
    context::Context,
};
use rand::{thread_rng, Rng};
use std::mem::size_of;
use std::sync::Arc;

const MAX_CYCLES: u64 = 1_000_000_000;

fn calculate_sha256(buf: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut c = Sha256::new();
    c.update(buf);
    c.finalize().into()
}

trait Auth {
    fn args(&self, entry_type: EntryCategoryType) -> Bytes;
    fn sign(&self, msg: &[u8; 32]) -> Bytes;
    fn sign_size(&self) -> usize;
}

#[derive(Clone)]
struct CKbAuth {
    privkey: Privkey,
}
impl CKbAuth {
    fn new() -> Self {
        Self {
            privkey: Generator::random_privkey(),
        }
    }
}

impl Auth for CKbAuth {
    fn args(&self, entry_type: EntryCategoryType) -> Bytes {
        struct EntryType {
            _code_hash: [u8; 20],
            _hash_type: u8,
            _entry_category: u8,
        }
        let mut bytes = BytesMut::with_capacity(size_of::<CkbAuthType>() + size_of::<EntryType>());

        let pub_key = self.privkey.pubkey().expect("pubkey").serialize();
        let pub_hash = blake2b_256(pub_key.as_slice());

        let ckb_auth_type = CkbAuthType {
            algorithm_id: AuthAlgorithmIdType::Ckb,
            pubkey_hash: pub_hash[..20].try_into().unwrap(),
        };
        bytes.put_u8(ckb_auth_type.algorithm_id.into());
        bytes.put(Bytes::from(ckb_auth_type.pubkey_hash.to_vec()));

        bytes.put(CellOutput::calc_data_hash(&Loader::default().load_auth()).as_bytes());
        bytes.put_u8(ScriptHashType::Data1.into());
        bytes.put_u8(entry_type.clone() as u8);

        bytes.freeze()
    }
    fn sign(&self, msg: &[u8; 32]) -> Bytes {
        // convert message
        let msg = H256::from(msg.clone());

        let sig = self
            .privkey
            .sign_recoverable(&msg)
            .expect("sign")
            .serialize();
        Bytes::from(sig)
    }
    fn sign_size(&self) -> usize {
        // The fixed length of ckb signature is 65
        65
    }
}

#[derive(Clone)]
pub struct Secp256r1Auth {
    pub key: Arc<p256::ecdsa::SigningKey>,
}

impl Secp256r1Auth {
    pub fn new() -> Secp256r1Auth {
        use p256::ecdsa::SigningKey;
        const SECRET_KEY: [u8; 32] = [
            0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58, 0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4,
            0x77, 0x1a, 0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac, 0xca, 0x54, 0xa5, 0x6d,
            0xda, 0x72, 0xb4, 0x64,
        ];

        let sk = SigningKey::from_bytes(&SECRET_KEY).unwrap();
        Self { key: Arc::new(sk) }
    }
    pub fn get_pub_key(&self) -> p256::ecdsa::VerifyingKey {
        let pk = self.key.verifying_key();
        pk
    }
    pub fn get_pub_key_bytes(&self) -> Vec<u8> {
        let pub_key = self.get_pub_key();
        let encoded_point = pub_key.to_encoded_point(false);
        let bytes = encoded_point.as_bytes();
        // The first byte is always 0x04, which is the tag for Uncompressed point.
        // See https://docs.rs/sec1/latest/sec1/point/enum.Tag.html#variants
        // Discard it as we always use x, y coordinates to encode pubkey.
        bytes[1..].to_vec()
    }
}
impl Auth for Secp256r1Auth {
    fn args(&self, entry_type: EntryCategoryType) -> Bytes {
        struct EntryType {
            _code_hash: [u8; 20],
            _hash_type: u8,
            _entry_category: u8,
        }
        let mut bytes = BytesMut::with_capacity(size_of::<CkbAuthType>() + size_of::<EntryType>());

        let pub_key = self.get_pub_key_bytes();
        let hash = blake2b_256(&pub_key);

        let ckb_auth_type = CkbAuthType {
            algorithm_id: AuthAlgorithmIdType::Secp256r1,
            pubkey_hash: hash[..20].try_into().unwrap(),
        };
        bytes.put_u8(ckb_auth_type.algorithm_id.into());
        bytes.put(Bytes::from(ckb_auth_type.pubkey_hash.to_vec()));

        bytes.put(CellOutput::calc_data_hash(&Loader::default().load_libecc_auth()).as_bytes());
        bytes.put_u8(ScriptHashType::Data1.into());
        bytes.put_u8(entry_type.clone() as u8);

        bytes.freeze()
    }
    fn sign(&self, msg: &[u8; 32]) -> Bytes {
        let msg = H256::from(msg.clone());
        use p256::ecdsa::{signature::Signer, Signature};

        let pub_key = self.get_pub_key_bytes();
        let _hash = calculate_sha256(msg.as_bytes());

        // Note by default, p256 will sign the sha256 hash of the message.
        // So we don't need to do any hashing here.
        let signature: Signature = self.key.sign(msg.as_bytes());
        let signature = signature.to_vec();
        let signature: Vec<u8> = pub_key.iter().chain(&signature).map(|x| *x).collect();

        signature.into()
    }
    fn sign_size(&self) -> usize {
        128
    }
}

fn gen_tx(ctx: &mut Context, grouped_args: Vec<(Bytes, usize, usize)>) -> TransactionView {
    let mut rng = thread_rng();
    let loader = Loader::default();

    let auth_demo_outpoint = ctx.deploy_cell(loader.load_demo());
    let sighash_dl_out_point = ctx.deploy_cell(loader.load_auth());
    let sighash_dl_libecc_out_point = ctx.deploy_cell(loader.load_libecc_auth());
    let secp256k1_data_out_point = ctx.deploy_cell(loader.load_secp256k1_data());

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_dl_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_dl_libecc_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp256k1_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    for (args, sign_size, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let script = ctx
                .build_script(&auth_demo_outpoint, args.clone())
                .expect("generate lock script");
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            let input_cell = CellInputBuilder::default()
                .previous_output(ctx.create_cell(previous_output_cell, Bytes::default()))
                .build();

            let mut random_extra_witness = Vec::new();
            random_extra_witness.resize(sign_size, 0u8);
            rng.fill(random_extra_witness.as_mut_slice());

            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(Bytes::from(random_extra_witness.to_vec())).pack())
                .build();
            tx_builder = tx_builder
                .input(input_cell)
                .witness(witness_args.as_bytes().pack());
        }
    }

    ctx.complete_tx(tx_builder.build())
}

fn sign_tx(tx: TransactionView, auths: &Vec<Box<dyn Auth>>, sign_size: usize) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    let begin_index = 0;
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<ckb_testtool::ckb_types::packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(sign_size, 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + witnesses_len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);

                let mut sign_buf = BytesMut::new();

                for auth in auths {
                    let sig;
                    sig = auth.sign(&message);
                    sign_buf.put_u16_le(sig.len() as u16);
                    sign_buf.put(sig);
                }

                witness
                    .as_builder()
                    .lock(Some(sign_buf.freeze()).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

const CKB_SIGN_GROUP_SIZE: usize = 1;

fn get_auth_args(auths: &Vec<Box<dyn Auth>>, entry_type: EntryCategoryType) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + auths.len() * 55);

    buf.put_u8(auths.len() as u8);
    for auth in auths {
        buf.put(auth.args(entry_type.clone()));
    }

    buf.freeze()
}

#[test]
fn test_exec() {
    let auths: Vec<Box<dyn Auth>> = vec![Box::new(CKbAuth::new()), Box::new(Secp256r1Auth::new())];
    let mut sign_size = 0;
    for auth in &auths {
        sign_size += 2 + auth.sign_size();
    }

    let mut ctx = Context::default();
    let tx = gen_tx(
        &mut ctx,
        vec![(
            get_auth_args(&auths, EntryCategoryType::Exec),
            sign_size,
            CKB_SIGN_GROUP_SIZE,
        )],
    );
    let tx = sign_tx(tx, &auths, sign_size);

    ctx.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
}

#[test]
fn test_dll() {
    let auths: Vec<Box<dyn Auth>> = vec![Box::new(CKbAuth::new()), Box::new(Secp256r1Auth::new())];
    let mut sign_size = 0;
    for auth in &auths {
        sign_size += 2 + auth.sign_size();
    }

    let mut ctx = Context::default();
    let tx = gen_tx(
        &mut ctx,
        vec![(
            get_auth_args(&auths, EntryCategoryType::DynamicLibrary),
            sign_size,
            CKB_SIGN_GROUP_SIZE,
        )],
    );
    let tx = sign_tx(tx, &auths, sign_size);

    ctx.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
}

#[test]
fn test_spawn() {
    let auths: Vec<Box<dyn Auth>> = vec![Box::new(CKbAuth::new()), Box::new(Secp256r1Auth::new())];
    let mut sign_size = 0;
    for auth in &auths {
        sign_size += 2 + auth.sign_size();
    }

    let mut ctx = Context::default();
    let tx = gen_tx(
        &mut ctx,
        vec![(
            get_auth_args(&auths, EntryCategoryType::Spawn),
            sign_size,
            CKB_SIGN_GROUP_SIZE,
        )],
    );
    let tx = sign_tx(tx, &auths, sign_size);

    ctx.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
}
