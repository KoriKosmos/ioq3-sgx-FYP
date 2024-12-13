#define ENCLAVE_FILE "TestEnclave.signed.dll"
#include "sgx_urts.h"
#include "TestEnclave_u.h"
#include <stdio.h>
#include <time.h>

// Implementation of ocall_log_message
void ocall_log_message(const char* message) {
    printf("Log: %s\n", message);
}

// Implementation of ocall_get_random_seed
int ocall_get_random_seed() {
    return (int)time(NULL); // Return current time as a seed
}

int main() {
    sgx_enclave_id_t eid;           // Enclave ID
    sgx_status_t ret = SGX_SUCCESS; // SGX status
    sgx_launch_token_t token = { 0 }; // Launch token
    int updated = 0;

    // Create the enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to create enclave.\n", ret);
        return -1;
    }

    int body_parts[3] = { 0, 1, 2 }; // 0: Head, 1: Torso, 2: Legs
    const char* body_part_names[] = { "Head", "Torso", "Legs" };
    int damage = 0;

    for (int i = 0; i < 3; ++i) {
        // Call ECALL to calculate damage
        ret = ecall_calculate_damage(eid, body_parts[i], &damage);
        if (ret != SGX_SUCCESS) {
            printf("\nApp: error %#x during ECALL.\n", ret);
            sgx_destroy_enclave(eid);
            return -1;
        }

        printf("\nApp: Damage to %s: %d\n", body_part_names[i], damage);
    }

    // Destroy the enclave when all ECALLs are finished
    if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
        printf("\nApp: error, failed to destroy enclave.\n");
    }

    getchar(); // Wait for user input before closing
    return 0;
}
