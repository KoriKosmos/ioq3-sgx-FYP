a// File: EnclaveService.cpp
#include <windows.h>
#include <cstdio>
#include "sgx_urts.h"
#include "DevEnclave_u.h"  // Generated header

#define ENCLAVE_FILE "DevEnclave.signed.dll"
#define PIPE_NAME "\\\\.\\pipe\\SGX_ANTICHEAT"

sgx_enclave_id_t g_enclaveId = 0;

// Simple OCALL implementation
void ocall_log(const char* message) {
    printf("Enclave Log: %s\n", message);
}

int main() {
    // 1. Create the enclave.
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &g_enclaveId, NULL);
    if (ret != SGX_SUCCESS) {
        printf("sgx_create_enclave failed: %x\n", ret);
        return 1;
    }
    printf("Enclave created successfully.\n");

    // 2. Create the named pipe.
    HANDLE hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,        // max instances
        1024,     // output buffer size
        1024,     // input buffer size
        0,        // default timeout
        NULL      // no security attributes
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe failed.\n");
        return 1;
    }
    printf("Waiting for a connection from ioq3...\n");

    // 3. Wait for the 32-bit ioq3 client to connect.
    BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        printf("ConnectNamedPipe failed.\n");
        CloseHandle(hPipe);
        return 1;
    }
    printf("Client connected.\n");

    // 4. Process incoming requests:
    //    For simplicity, assume each request is a structure of 4 ints:
    //    attackerId, targetId, baseDamage, weaponType.
    //    The enclave returns a single int (calculated damage).
    while (true) {
        int request[4] = { 0 };
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hPipe, request, sizeof(request), &bytesRead, NULL);
        if (!ok || bytesRead != sizeof(request)) {
            printf("Pipe read failed or client disconnected.\n");
            break;
        }

        int attackerId = request[0];
        int targetId = request[1];
        int baseDamage = request[2];
        int weaponType = request[3];

        int finalDamage = 0;
        // Call the enclave ECALL (assumes a similar function exists; update if needed)
        ret = ecall_calculate_damage(g_enclaveId, &finalDamage, attackerId, targetId, baseDamage, weaponType);
        if (ret != SGX_SUCCESS) {
            // Fallback behavior: use baseDamage if enclave call fails.
            finalDamage = baseDamage;
        }

        DWORD bytesWritten = 0;
        ok = WriteFile(hPipe, &finalDamage, sizeof(finalDamage), &bytesWritten, NULL);
        if (!ok || bytesWritten != sizeof(finalDamage)) {
            printf("Pipe write failed or client disconnected.\n");
            break;
        }
    }

    CloseHandle(hPipe);
    sgx_destroy_enclave(g_enclaveId);
    return 0;
}
