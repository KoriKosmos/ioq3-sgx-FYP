#include "sgx_urts.h"
#include "AntiCheatEnclave_u.h" // Auto-generated from edger8r
#include "../shared/shared_structs.h"
#include <cstdio>
#include <cstdlib>

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

    // Construct simulated shot input using field assignments
    ShotData shot;
    shot.attacker_id = 42;
    shot.target_id = 69;
    shot.weapon_type = 10;     // Example: railgun
    shot.hit_location = 0;     // Example: HEAD
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
        if (is_valid) {
            printf("Host: Shot is VALID ✅\n");
        }
        else {
            printf("Host: Shot is INVALID ❌ (possible cheat detected)\n");
        }
    }

    sgx_destroy_enclave(eid);
    printf("Host: Enclave destroyed.\n");

    return 0;
}
