#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "sgx_urts.h"
#include "AntiCheatEnclave_u.h"
#include "../shared/enclave_ipc.h"

#define ENCLAVE_PATH "AntiCheatEnclave.signed.dll"

sgx_enclave_id_t eid = 0;

void ocall_log_message(const char* msg) {
    printf("[ENCLAVE LOG] %s\n", msg);
}

int main() {
    sgx_status_t ret;
    sgx_launch_token_t token = { 0 };
    int updated = 0;

    printf("Creating enclave...\n");
    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &updated, &eid, nullptr);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave: %#x\n", ret);
        return -1;
    }

    printf("Enclave created.\n");

    // Simulate receiving encrypted message from ioquake3
    EncryptedMessage encrypted_in = {}; // You’ll later fill this from game logic
    EncryptedMessage encrypted_out = {};

    // Simulated call: decrypt, validate, re-encrypt
    sgx_status_t decrypt_ret, encrypt_ret;

    DamageInput input;
    ret = ecall_decrypt_message(
        eid, &decrypt_ret,
        encrypted_in.ciphertext,
        encrypted_in.tag,
        encrypted_in.iv,
        encrypted_in.length,
        16,
        12,
        reinterpret_cast<uint8_t*>(&input)
    );

    if (ret != SGX_SUCCESS || decrypt_ret != SGX_SUCCESS) {
        printf("Decryption failed (ret=%#x, enclave_ret=%#x)\n", ret, decrypt_ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    int final_dmg = 0, final_armor = 0, final_kb = 0;
    ret = ecall_validate_damage(
        eid, &decrypt_ret,
        input.weapon_damage, input.target_armor, input.dflags,
        &final_dmg, &final_armor, &final_kb
    );

    if (ret != SGX_SUCCESS || decrypt_ret != SGX_SUCCESS) {
        printf("Validation failed (ret=%#x, enclave_ret=%#x)\n", ret, decrypt_ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    DamageOutput output = { final_dmg, final_armor, final_kb };
    uint8_t iv_out[12] = { 0 }; // Use nonce later
    uint8_t mac[16] = { 0 };

    ret = ecall_encrypt_message(
        eid, &encrypt_ret,
        reinterpret_cast<const uint8_t*>(&output),
        sizeof(DamageOutput),
        iv_out,
        encrypted_out.ciphertext,
        encrypted_out.tag
    );

    if (ret != SGX_SUCCESS || encrypt_ret != SGX_SUCCESS) {
        printf("Encryption failed (ret=%#x, enclave_ret=%#x)\n", ret, encrypt_ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    memcpy(encrypted_out.iv, iv_out, 12);
    encrypted_out.length = sizeof(DamageOutput);

    printf("Pipeline completed. Result is encrypted and ready to return to game.\n");

    sgx_destroy_enclave(eid);
    printf("Enclave destroyed.\n");

    return 0;
}
