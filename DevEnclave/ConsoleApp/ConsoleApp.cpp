#include <Windows.h>
#include <stdio.h>
#include "sgx_urts.h"
#include "DevEnclave_u.h"

#define ENCLAVE_FILE _T("DevEnclave.signed.dll")

int main() {
    sgx_enclave_id_t eid;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("[-] Failed to create enclave: 0x%X\n", ret);
        return 1;
    }

    int result = -1;
    int current = 90, damage = 30, max = 100;
    ret = update_health(eid, current, damage, max, &result);

    if (ret != SGX_SUCCESS) {
        printf("[-] ECALL failed: 0x%X\n", ret);
    }
    else {
        printf("[+] update_health(%d, %d, %d) = %d\n", current, damage, max, result);
    }

    sgx_destroy_enclave(eid);
    return 0;
}
