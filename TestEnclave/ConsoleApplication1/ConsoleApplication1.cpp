#include <stdio.h>
#include <stdint.h>
#include "sgx_urts.h"
#include "TestEnclave_u.h"

// Global enclave ID
sgx_enclave_id_t global_eid = 0;

int main() {
    printf("[App] Starting the application.\n");

    // Create the enclave
    sgx_status_t status = sgx_create_enclave(L"TestEnclave.signed.dll", SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (status != SGX_SUCCESS) {
        printf("[App] Failed to create enclave, SGX status: %d\n", status);
        return -1;
    }
    printf("[App] Enclave created successfully.\n");

    // Call the dummy ECALL
    status = ecall_dummy(global_eid);
    if (status != SGX_SUCCESS) {
        printf("[App] Failed to call ecall_dummy, SGX status: %d\n", status);
    }
    else {
        printf("[App] ECALL dummy executed successfully.\n");
    }

    // Destroy the enclave
    sgx_destroy_enclave(global_eid);
    printf("[App] Enclave destroyed successfully.\n");

    return 0;
}
