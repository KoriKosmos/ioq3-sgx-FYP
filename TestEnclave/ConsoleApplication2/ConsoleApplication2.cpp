#define ENCLAVE_FILE "TestEnclave.signed.dll"
#include "sgx_urts.h"
#include "TestEnclave_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Dummy OCALL for logging a message
void ocall_log_message(const char* message) {
    if (message) {
        printf("OCALL Log: %s\n", message);
    }
}

// Dummy OCALL to generate a random seed
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

    int health = 100; // Starting health
    const char* potion_names[] = { "Health", "Damage", "Berserkers", "Weakness", "Normalcy" };

    srand((unsigned int)time(NULL)); // Seed the random number generator

    printf("\nApp: Starting potion consumption simulation...\n");
    for (int i = 0; i < 5; ++i) {
        int potion_type = rand() % 5; // Generate a random potion type (0-4)

        // Call ECALL to consume potion
        ret = ecall_consume_potion(eid, potion_type, &health);
        if (ret != SGX_SUCCESS) {
            printf("\nApp: error %#x during ECALL.\n", ret);
            sgx_destroy_enclave(eid);
            return -1;
        }

        printf("App: Consumed Potion of %s. Current health: %d\n", potion_names[potion_type], health);

        // Check health boundaries
        if (health <= 0) {
            printf("App: YOU DIED!\n");
            break;
        }
        else if (health >= 1000) {
            printf("App: GODLIKE!!!\n");
            break;
        }
    }

    // Destroy the enclave when all ECALLs are finished
    if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
        printf("\nApp: error, failed to destroy enclave.\n");
    }

    getchar(); // Wait for user input before closing
    return 0;
}
