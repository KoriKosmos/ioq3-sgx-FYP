#include "sgx_urts.h"
#include "AntiCheatEnclave_u.h" // Auto-generated from edger8r
#include "../shared/shared_structs.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define ENCLAVE_PATH "AntiCheatEnclave.signed.dll"

void ocall_log_message(const char* message) {
    printf("ENCLAVE LOG: %s\n", message);
}

int main() {
    sgx_enclave_id_t eid;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = { 0 };
    int updated = 0;

    printf("Host: Creating enclave...\n");

    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &updated, &eid, nullptr);
    if (ret != SGX_SUCCESS) {
        printf("Host: Failed to create enclave (error code: %#x)\n", ret);
        return -1;
    }

    printf("Host: Enclave created successfully.\n");

    // Step 1: Generate enclave TLS keypair
    sgx_status_t enclave_ret;
    ret = ecall_generate_tls_keypair(eid, &enclave_ret);

    if (ret != SGX_SUCCESS || enclave_ret != SGX_SUCCESS) {
        printf("Host: Failed to generate enclave TLS keypair (ret=%#x, enclave_ret=%#x)\n", ret, enclave_ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    // Step 2: Retrieve enclave public key
    uint8_t pub_x[32], pub_y[32];
    ret = ecall_get_tls_public_key(eid, &enclave_ret, pub_x, pub_y, 32);
    if (ret != SGX_SUCCESS || enclave_ret != SGX_SUCCESS) {
        printf("Host: Failed to retrieve enclave public key (ret=%#x, enclave_ret=%#x)\n", ret, enclave_ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    printf("Host: Retrieved enclave TLS public key:\n");
    printf("  X: ");
    for (int i = 0; i < 32; ++i) printf("%02X", pub_x[i]);
    printf("\n  Y: ");
    for (int i = 0; i < 32; ++i) printf("%02X", pub_y[i]);
    printf("\n");

    // Simulate a test shot (same as before)
    ShotData shot;
    shot.attacker_id = 42;
    shot.target_id = 69;
    shot.weapon_type = 10;     // Example: railgun
    shot.hit_location = 0;     // HEAD
    shot.distance = 95.0f;
    shot.damage = 250;

    int is_valid = 0;

    printf("Host: Sending shot to enclave for validation...\n");

    ret = ecall_validate_shot(
        eid,
        shot.attacker_id,
        shot.target_id,
        shot.weapon_type,
        shot.hit_location,
        shot.distance,
        shot.damage,
        &is_valid
    );

    if (ret != SGX_SUCCESS) {
        printf("Host: ECALL failed with error code %#x\n", ret);
    }
    else {
        printf("Host: Shot is %s\n", is_valid ? "VALID" : "INVALID (possible cheat detected)");
    }

    sgx_destroy_enclave(eid);
    printf("\nHost: Enclave destroyed.\n");

    return 0;
}
