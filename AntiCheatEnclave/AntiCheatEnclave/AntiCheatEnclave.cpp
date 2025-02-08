#include "sgx_tcrypto.h"
#include "AntiCheatEnclave_t.h"
#include <string.h>
#include <cstdio>
#include <cstring>
#include "../shared/shared_structs.h"

sgx_ec256_private_t enclave_tls_priv_key;
sgx_ec256_public_t enclave_tls_pub_key;

sgx_status_t ecall_generate_tls_keypair() {
    sgx_ecc_state_handle_t ecc_handle = nullptr;
    sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
    if (status != SGX_SUCCESS) return status;

    status = sgx_ecc256_create_key_pair(&enclave_tls_priv_key, &enclave_tls_pub_key, ecc_handle);
    sgx_ecc256_close_context(ecc_handle);
    return status;
}


sgx_status_t ecall_get_tls_public_key(uint8_t* pub_key_x, uint8_t* pub_key_y, size_t len) {
    if (!pub_key_x || !pub_key_y || len < sizeof(enclave_tls_pub_key.gx)) return SGX_ERROR_INVALID_PARAMETER;

    memcpy(pub_key_x, enclave_tls_pub_key.gx, sizeof(enclave_tls_pub_key.gx));
    memcpy(pub_key_y, enclave_tls_pub_key.gy, sizeof(enclave_tls_pub_key.gy));
    return SGX_SUCCESS;
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

