#include <stdio.h>
#include "sgx_urts.h"
#include "AntiCheatEnclave_u.h"

#define ENCLAVE_FILE "AntiCheatEnclave.signed.dll"
#define SGX_DEBUG_FLAG 1

// OCALL: receive log messages from the enclave
void ocall_log_message(const char* message) {
    printf("LOG (Enclave): %s\n", message);
}

int main() {
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = { 0 };
    int updated = 0;

    // Create enclave
    sgx_status_t ret = sgx_create_enclave(
        ENCLAVE_FILE,
        SGX_DEBUG_FLAG,
        &token,
        &updated,
        &eid,
        NULL
    );

    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave. Error code: 0x%X\n", ret);
        return -1;
    }

    printf("Enclave created successfully.\n");

    // Input data for anti-cheat test
    int attacker_id = 42;
    int target_id = 69;
    int weapon_type = 0;   // 0 = rifle
    int hit_location = 0;  // 0 = head
    float distance = 75.5f;

    int damage = 0;
    int is_valid = 0;

    // Call into enclave to validate damage
    ret = ecall_validate_damage(
        eid,
        attacker_id,
        target_id,
        weapon_type,
        hit_location,
        distance,
        &damage,
        &is_valid
    );

    if (ret != SGX_SUCCESS) {
        printf("ECALL failed. Error code: 0x%X\n", ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    // Output result
    if (is_valid != 0) {
        printf("Valid damage: %d\n", damage);
    }
    else {
        printf("Invalid shot. Possible cheat.\n");
    }

    // Destroy enclave
    sgx_destroy_enclave(eid);
    printf("Enclave destroyed.\n");

    return 0;
}
