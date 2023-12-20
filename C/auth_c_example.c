// This on-chain script is for testing purposes:
// Using multiple different versions of ckb-auth within a single transaction.
//
// Script Args:
// In Args, there will be multiple sets of args for auth_c_lock.c.
//  The first element in Args indicates the number of sets,
//    so the length of Args is 1 + n * 54.
//
// Witness:
// Corresponding ckb_auth for each set sequentially.

#include "blake2b.h"
#include "blockchain.h"
#include "ckb_auth.h"
#include "ckb_consts.h"
#include "ckb_syscalls.h"

#define BLAKE2B_BLOCK_SIZE 32
#define TEMP_SIZE 32768
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768

#define ONE_BATCH_SIZE 32768

#define CKB_AUTH_ARGS_SIZE (CKB_AUTH_LEN + BLAKE2B_BLOCK_SIZE + 1 + 1)

static int extract_witness_lock(uint8_t *witness, uint64_t len,
                                mol_seg_t *lock_bytes_seg) {
    if (len < 20) {
        return CKB_INVALID_DATA;
    }
    uint32_t lock_length = *((uint32_t *)(&witness[16]));
    if (len < 20 + lock_length) {
        return CKB_INVALID_DATA;
    } else {
        lock_bytes_seg->ptr = &witness[20];
        lock_bytes_seg->size = lock_length;
    }
    return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state *ctx, size_t start, size_t index,
                          size_t source, bool hash_length) {
    uint8_t temp[ONE_BATCH_SIZE];
    uint64_t len = ONE_BATCH_SIZE;
    int ret = ckb_load_witness(temp, &len, start, index, source);
    if (ret != CKB_SUCCESS) {
        return ret;
    }
    if (hash_length) {
        blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
    }
    uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
    blake2b_update(ctx, temp, offset);
    while (offset < len) {
        uint64_t current_len = ONE_BATCH_SIZE;
        ret =
            ckb_load_witness(temp, &current_len, start + offset, index, source);
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        uint64_t current_read =
            (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
        blake2b_update(ctx, temp, current_read);
        offset += current_read;
    }
    return CKB_SUCCESS;
}

int generate_sighash_all(uint8_t *msg, size_t msg_len) {
    int ret;
    uint64_t len = 0;
    unsigned char temp[MAX_WITNESS_SIZE];
    uint64_t read_len = MAX_WITNESS_SIZE;
    uint64_t witness_len = MAX_WITNESS_SIZE;

    if (msg_len < BLAKE2B_BLOCK_SIZE) {
        return CKB_INVALID_DATA;
    }

    /* Load witness of first input */
    ret = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
        return CKB_INVALID_DATA;
    }
    witness_len = read_len;
    if (read_len > MAX_WITNESS_SIZE) {
        read_len = MAX_WITNESS_SIZE;
    }

    /* load signature */
    mol_seg_t lock_bytes_seg;
    ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
    if (ret != 0) {
        return CKB_INVALID_DATA;
    }

    /* Load tx hash */
    unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
    len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_load_tx_hash(tx_hash, &len, 0);
    if (ret != CKB_SUCCESS) {
        return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
        return CKB_INVALID_DATA;
    }

    /* Prepare sign message */
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

    /* Clear lock field to zero, then digest the first witness
     * lock_bytes_seg.ptr actually points to the memory in temp buffer
     * */
    memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
    blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, read_len);

    // remaining of first witness
    if (read_len < witness_len) {
        ret = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                    CKB_SOURCE_GROUP_INPUT, false);
        if (ret != CKB_SUCCESS) {
            return CKB_INVALID_DATA;
        }
    }

    // Digest same group witnesses
    size_t i = 1;
    while (1) {
        ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT,
                                    true);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        if (ret != CKB_SUCCESS) {
            return CKB_INVALID_DATA;
        }
        i += 1;
    }

    // Digest witnesses that not covered by inputs
    i = (size_t)ckb_calculate_inputs_len();
    while (1) {
        ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        if (ret != CKB_SUCCESS) {
            return CKB_INVALID_DATA;
        }
        i += 1;
    }

    blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);

    return 0;
}

int main() {
    int ret;
    uint64_t len = 0;
    unsigned char temp[TEMP_SIZE];

    unsigned char script[SCRIPT_SIZE];
    len = SCRIPT_SIZE;
    ret = ckb_load_script(script, &len, 0);
    if (ret != CKB_SUCCESS) {
        return CKB_INVALID_DATA;
    }
    if (len > SCRIPT_SIZE) {
        return CKB_INVALID_DATA;
    }
    mol_seg_t script_seg;
    script_seg.ptr = (uint8_t *)script;
    script_seg.size = len;

    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
        return CKB_INVALID_DATA;
    }

    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

    if (args_bytes_seg.size < 1) {
        return CKB_INVALID_DATA;
    }
    size_t auth_num = args_bytes_seg.ptr[0];
    // auth 21bytes + code_hash 32bytes + hash_type 1byte + entry_category 1byte
    if (auth_num == 0 ||
        args_bytes_seg.size != auth_num * CKB_AUTH_ARGS_SIZE + 1) {
        return CKB_INVALID_DATA;
    }

    // Load the first witness, or the witness of the same index as the first
    // input using current script.
    uint64_t witness_len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
        return CKB_INVALID_DATA;
    }

    mol_seg_t lock_bytes_seg;
    ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
    if (ret != 0) {
        return CKB_INVALID_DATA;
    }
    uint8_t msg32[32];
    ret = generate_sighash_all(msg32, 32);
    if (ret != 0) return CKB_INVALID_DATA;

    size_t witness_offset = 0;
    for (size_t i = 0; i < auth_num; i++) {
        size_t args_offset = 1 + CKB_AUTH_ARGS_SIZE * i;
        uint8_t *args = args_bytes_seg.ptr + args_offset;

        CkbAuthType auth;
        auth.algorithm_id = args[0];
        memcpy(&auth.content, args + 1, AUTH160_SIZE);

        CkbEntryType entry;
        memcpy(entry.code_hash, args + CKB_AUTH_LEN, BLAKE2B_BLOCK_SIZE);
        entry.hash_type = *(args + CKB_AUTH_LEN + BLAKE2B_BLOCK_SIZE);
        entry.entry_category = *(args + CKB_AUTH_LEN + BLAKE2B_BLOCK_SIZE + 1);

        if (lock_bytes_seg.size < witness_offset + 2) {
            return CKB_INVALID_DATA;
        }
        uint32_t sign_size = *(uint16_t *)(lock_bytes_seg.ptr + witness_offset);
        if (lock_bytes_seg.size < witness_offset + 2 + sign_size) {
            return CKB_INVALID_DATA;
        }
        uint8_t *signature = lock_bytes_seg.ptr + witness_offset + 2;
        witness_offset += sign_size + 2;

        ret = ckb_auth(&entry, &auth, signature, sign_size, msg32);
        if (ret) {
            return ret;
        }
    }
}
