// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
// use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/

use crate::error::Error;

use alloc::vec::Vec;
use ckb_auth_rs::{
    ckb_auth, generate_sighash_all, AuthAlgorithmIdType, CkbAuthError, CkbAuthType, CkbEntryType,
    EntryCategoryType,
};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*},
    high_level::{load_script, load_witness_args},
};
use core::mem::size_of;

const AUTH160_SIZE: usize = 20;
const CKB_AUTH_SIZE: usize = 1 + AUTH160_SIZE; // 21
const BLAKE2B_BLOCK_SIZE: usize = 32;

// ckb_auth + code_hash + hash_type + entry_type
const CKB_AUTH_ARGS_SIZE: usize = CKB_AUTH_SIZE + BLAKE2B_BLOCK_SIZE + 1 + 1;

// use ckb_std::debug;

fn get_transaction_info() -> Result<(Vec<u8>, Vec<u8>, [u8; 32]), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    let witness_args = load_witness_args(0, Source::GroupInput).map_err(|_| Error::WitnessError)?;
    let witness = witness_args
        .lock()
        .to_opt()
        .ok_or(CkbAuthError::SignatureMissing)?
        .raw_data();

    let message = generate_sighash_all().map_err(|_| Error::GeneratedMsgError)?;

    Ok((args.to_vec(), witness.to_vec(), message))
}

pub fn main() -> Result<(), Error> {
    let (args, witness, message) = get_transaction_info()?;

    if args.len() < 1 {
        return Err(Error::ArgsError);
    }
    let auth_count = args[0] as usize;
    if args.len() != 1 + CKB_AUTH_ARGS_SIZE * auth_count {
        return Err(Error::ArgsError);
    }

    let mut witness_offset = 0usize;
    for index in 0..auth_count {
        let args_offset = 1 + index * CKB_AUTH_ARGS_SIZE;
        let auth_id = args[args_offset];
        let pubkey_hash: [u8; AUTH160_SIZE] = args[args_offset + 1..args_offset + 1 + AUTH160_SIZE]
            .try_into()
            .unwrap();

        let code_hash: [u8; BLAKE2B_BLOCK_SIZE] = args
            [args_offset + 1 + AUTH160_SIZE..args_offset + 1 + AUTH160_SIZE + BLAKE2B_BLOCK_SIZE]
            .try_into()
            .unwrap();
        let hash_type = match args[args_offset + 1 + AUTH160_SIZE + BLAKE2B_BLOCK_SIZE] {
            0 => ScriptHashType::Data,
            1 => ScriptHashType::Type,
            2 => ScriptHashType::Data1,
            _ => {
                return Err(Error::ArgsError);
            }
        };
        let entry_type = args[args_offset + 1 + AUTH160_SIZE + BLAKE2B_BLOCK_SIZE + 1] as u8;

        let signature = {
            if witness.len() < witness_offset + size_of::<u16>() {
                return Err(Error::ArgsError);
            }
            let sign_size = u16::from_le_bytes(
                witness[witness_offset..witness_offset + size_of::<u16>()]
                    .try_into()
                    .unwrap(),
            ) as usize;

            if witness.len() < witness_offset + sign_size + size_of::<u16>() {
                return Err(Error::ArgsError);
            }
            let sign = witness
                [witness_offset + size_of::<u16>()..witness_offset + size_of::<u16>() + sign_size]
                .to_vec();
            witness_offset += size_of::<u16>() + sign_size;
            sign
        };

        let id = CkbAuthType {
            algorithm_id: AuthAlgorithmIdType::try_from(auth_id)
                .map_err(|f| CkbAuthError::from(f))?,
            pubkey_hash: pubkey_hash,
        };
        let entry = CkbEntryType {
            code_hash,
            hash_type,
            entry_category: EntryCategoryType::try_from(entry_type)
                .map_err(|f| CkbAuthError::from(f))
                .unwrap(),
        };
        ckb_auth(&entry, &id, &signature, &message)?;
    }

    Ok(())
}
