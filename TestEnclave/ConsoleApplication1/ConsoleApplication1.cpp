#define ENCLAVE_FILE "TestEnclave.signed.dll" // Remove the 'L' prefix
#define MAX_BUF_LEN 100

#include "sgx_urts.h"         // SGX untrusted runtime library
#include "TestEnclave_u.h"    // Updated to match
#include <stdio.h>
#include <string.h>

int main() {
    sgx_enclave_id_t eid;           // Enclave ID
    sgx_status_t ret = SGX_SUCCESS; // SGX status
    sgx_launch_token_t token = { 0 }; // Launch token
    int updated = 0;

    char buffer[MAX_BUF_LEN] = "Hello World!"; // Initial buffer content

    // Create the enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x, failed to create enclave.\n", ret);
        return -1;
    }

    printf("\nApp: Buffer before ECALL: %s\n", buffer);

    // Call ECALL to modify the buffer in the enclave
    ret = enclaveChangeBuffer(eid, buffer, MAX_BUF_LEN);
    if (ret != SGX_SUCCESS) {
        printf("\nApp: error %#x during ECALL.\n", ret);
        sgx_destroy_enclave(eid);
        return -1;
    }

    printf("\nApp: Buffer after ECALL: %s\n", buffer);

    // Destroy the enclave when all ECALLs are finished
    if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
        printf("\nApp: error, failed to destroy enclave.\n");
    }

    getchar(); // Wait for user input before closing
    return 0;
}
