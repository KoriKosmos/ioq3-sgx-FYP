#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "AntiCheatEnclave_t.h"
#include <string.h>
#include <cstdio>
#include <cstring>
#include "../shared/shared_structs.h"

sgx_ec256_private_t enclave_key_priv;
sgx_ec256_public_t enclave_key_pub;
sgx_ec256_public_t host_pubkey;
sgx_ec256_dh_shared_t shared_secret;
sgx_aes_gcm_128bit_key_t session_key;

sgx_status_t ecall_generate_keypair() {
    sgx_ecc_state_handle_t ecc_handle = nullptr;
    sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) return status;

    status = sgx_ecc256_create_key_pair(&enclave_key_priv, &enclave_key_pub, ecc_handle);
    sgx_ecc256_close_context(ecc_handle);
    return status;
}


sgx_status_t ecall_get_public_key(uint8_t* pub_key_x, uint8_t* pub_key_y, size_t len) {
    if (!pub_key_x || !pub_key_y || len < sizeof(enclave_key_pub.gx)) return SGX_ERROR_INVALID_PARAMETER;

    memcpy(pub_key_x, enclave_key_pub.gx, sizeof(enclave_key_pub.gx));
    memcpy(pub_key_y, enclave_key_pub.gy, sizeof(enclave_key_pub.gy));
    return SGX_SUCCESS;
}

sgx_status_t ecall_store_host_pubkey(const uint8_t* host_pubkey_x, const uint8_t* host_pubkey_y, size_t len) {
    if (!host_pubkey_x || !host_pubkey_y || len < sizeof(host_pubkey.gx)) return SGX_ERROR_INVALID_PARAMETER;

    memcpy(host_pubkey.gx, host_pubkey_x, sizeof(host_pubkey.gx));
    memcpy(host_pubkey.gy, host_pubkey_y, sizeof(host_pubkey.gy));
    return SGX_SUCCESS;
}

sgx_status_t ecall_derive_shared_secret() {
    sgx_ecc_state_handle_t ecc_handle = nullptr;
    sgx_ec256_dh_shared_t shared_secret;

    sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) return status;

    // Derive shared secret from enclave's private key and host's public key
    status = sgx_ecc256_compute_shared_dhkey(
        &enclave_key_priv,
        &host_pubkey,
        &shared_secret,
        ecc_handle // corrected from 'handle'
    );

    sgx_ecc256_close_context(ecc_handle);
    if (status != SGX_SUCCESS) return status;

    // Hash the shared secret to derive session AES-GCM key
    status = sgx_sha256_msg(
        reinterpret_cast<const uint8_t*>(&shared_secret),
        sizeof(shared_secret),
        reinterpret_cast<sgx_sha256_hash_t*>(&session_key)
    );

    if (status != SGX_SUCCESS) return status;

    ocall_log_message("Enclave: Derived session key from shared secret.");
    return SGX_SUCCESS;
}

sgx_status_t ecall_encrypt_message(
    const uint8_t* plaintext, size_t msg_len,
    const uint8_t* iv,
    uint8_t* ciphertext,
    uint8_t* mac
) {
    if (!plaintext || !iv || !ciphertext || !mac || msg_len == 0)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_aes_gcm_128bit_key_t key;
    memcpy(&key, session_key, sizeof(sgx_aes_gcm_128bit_key_t));

    sgx_status_t status = sgx_rijndael128GCM_encrypt(
        &key,
        plaintext,
        msg_len,
        ciphertext,
        iv,
        12,
        nullptr,
        0,
        reinterpret_cast<sgx_aes_gcm_128bit_tag_t*>(mac)
    );

    return status;
}

sgx_status_t ecall_decrypt_message(
    const uint8_t* ciphertext,
    const uint8_t* tag,
    const uint8_t* iv,
    size_t ct_len,
    size_t tag_len,
    size_t iv_len,
    uint8_t* plaintext
) {
    if (!ciphertext || !tag || !iv || !plaintext)
        return SGX_ERROR_INVALID_PARAMETER;

    if (tag_len != 16 || iv_len != 12)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_aes_gcm_128bit_key_t key;
    memcpy(&key, session_key, sizeof(sgx_aes_gcm_128bit_key_t));

    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &key,
        ciphertext,
        ct_len,
        plaintext,
        iv,
        static_cast<uint32_t>(iv_len),
        nullptr,
        0,
        reinterpret_cast<const sgx_aes_gcm_128bit_tag_t*>(tag)
    );

    if (status == SGX_SUCCESS) {
        ocall_log_message("Enclave: Message successfully decrypted.");
    }
    else {
        ocall_log_message("Enclave: Decryption failed or authentication tag mismatch.");
    }

    return status;
}


void ecall_validate_shot(
    int attacker_id,
    int target_id,
    int weapon_type,
    int hit_location,
    float distance,
    int damage,
    int* is_valid
) {
    char log_msg[128];

    // Simulated cheat check: sniper shots shouldn't hit from > 100m
    if (weapon_type == 10 /* e.g. railgun */ && distance > 100.0f) {
        snprintf(log_msg, sizeof(log_msg),
            "CHEAT DETECTED: %d → %d with weapon %d at %.2fm",
            attacker_id, target_id, weapon_type, distance);
        *is_valid = 0;
    }
    else {
        snprintf(log_msg, sizeof(log_msg),
            "Shot OK: %d → %d | Weapon: %d | Location: %d | Distance: %.2fm | Damage: %d",
            attacker_id, target_id, weapon_type, hit_location, distance, damage);
        *is_valid = 1;
    }

    ocall_log_message(log_msg);
}

