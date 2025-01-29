#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include "sgx_urts.h"
#include "Enclave_u.h"

#define ENCLAVE_FILE L"DevEnclave.signed.dll"

static sgx_enclave_id_t g_enclaveId = 0;

void ocall_log(const char* msg) {
    printf("Enclave: %s\n", msg);
}

int main() {
    // 1. Load the Enclave
    sgx_status_t ret = sgx_create_enclave("DevEnclave.signed.dll", SGX_DEBUG_FLAG, NULL, NULL, &g_enclaveId, NULL);
    if (ret != SGX_SUCCESS) {
        printf("sgx_create_enclave failed: %x\n", ret);
        return 1;
    }
    printf("Enclave loaded.\n");

    // 2. Create a named pipe for 32-bit ioq3 to connect
    HANDLE hPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\SGX_ANTICHEAT",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe failed.\n");
        return 1;
    }
    printf("Waiting for 32-bit ioq3 to connect...\n");

    // 3. Wait for client (ioq3) connection
    BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        printf("ConnectNamedPipe failed.\n");
        return 1;
    }
    printf("ioq3 connected.\n");

    // 4. Continuously read requests (attacker, target, baseDmg)
    //    and respond with final damage
    while (true) {
        int buf[3];
        DWORD bytesRead = 0;
        BOOL success = ReadFile(hPipe, buf, sizeof(buf), &bytesRead, NULL);
        if (!success || bytesRead == 0) {
            printf("Pipe read error or zero bytes, closing...\n");
            break;
        }

        int attacker = buf[0];
        int target = buf[1];
        int baseDmg = buf[2];
        int finalDmg = 0;

        // 5. Call enclave
        sgx_status_t ecallRet = ecall_calculate_damage(g_enclaveId, &finalDmg, attacker, target, baseDmg);
        if (ecallRet != SGX_SUCCESS) {
            finalDmg = baseDmg; // fallback
        }

        // 6. Send result back
        DWORD bytesWritten = 0;
        success = WriteFile(hPipe, &finalDmg, sizeof(int), &bytesWritten, NULL);
        if (!success || bytesWritten == 0) {
            printf("Pipe write error, closing...\n");
            break;
        }
    }

    CloseHandle(hPipe);
    sgx_destroy_enclave(g_enclaveId);
    return 0;
}