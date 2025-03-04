#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <stdint.h>
#include "enclave_ipc.h"
#include "sgx_urts.h"
#include "AntiCheatEnclave_u.h"

#define PIPE_NAME TEXT("\\\\.\\pipe\\IoQ3SecurePipe")
#define ENCLAVE_PATH "AntiCheatEnclave.signed.dll"

sgx_enclave_id_t eid = 0;

void ocall_log_message(const char* msg) {
    printf("[ENCLAVE LOG] %s\n", msg);
}

int main() {
    // === Enclave Init ===
    sgx_status_t ret;
    sgx_launch_token_t token = { 0 };
    int updated = 0;

    printf("Creating enclave...\n");
    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &updated, &eid, nullptr);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave: %#x\n", ret);
        return -1;
    }

    printf("Enclave created.\n");

    // === Create Named Pipe Server ===
    printf("Creating named pipe...\n");
    HANDLE hPipe = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        sizeof(EncryptedMessage),
        sizeof(EncryptedMessage),
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Failed to create named pipe. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("Waiting for client connection on pipe...\n");
    BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        printf("Failed to connect to pipe. Error: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("Client connected. Reading encrypted message...\n");

    EncryptedMessage in_msg = {};
    DWORD bytesRead = 0;
    BOOL success = ReadFile(hPipe, &in_msg, sizeof(EncryptedMessage), &bytesRead, NULL);
    if (!success || bytesRead != sizeof(EncryptedMessage)) {
        printf("Failed to read encrypted message from pipe.\n");
        CloseHandle(hPipe);
        return 1;
    }

    // === Decrypt inside enclave ===
    uint8_t decrypted[128] = {0};
    sgx_status_t dec_ret;
    ret = ecall_decrypt_message(
        eid, &dec_ret,
        in_msg.ciphertext,
        in_msg.tag,
        in_msg.iv,
        in_msg.length,
        16,
        12,
        decrypted
    );

    if (ret != SGX_SUCCESS || dec_ret != SGX_SUCCESS) {
        printf("Decryption failed.\n");
        CloseHandle(hPipe);
        return 1;
    }

    // === Interpret plaintext as 3 integers ===
    int damage = 0, armor = 0, dflags = 0;
    memcpy(&damage, &decrypted[0], sizeof(int));
    memcpy(&armor, &decrypted[4], sizeof(int));
    memcpy(&dflags, &decrypted[8], sizeof(int));

    // === Run validation logic ===
    int final_damage = 0, final_armor = 0, knockback = 0;
    ret = ecall_validate_damage(eid, &dec_ret, damage, armor, dflags, &final_damage, &final_armor, &knockback);
    if (ret != SGX_SUCCESS || dec_ret != SGX_SUCCESS) {
        printf("Validation ECALL failed.\n");
        CloseHandle(hPipe);
        return 1;
    }

    // === Encrypt response ===
    uint8_t plaintext_out[12] = {0};
    memcpy(&plaintext_out[0], &final_damage, sizeof(int));
    memcpy(&plaintext_out[4], &final_armor, sizeof(int));
    memcpy(&plaintext_out[8], &knockback, sizeof(int));

    EncryptedMessage out_msg = {};
    out_msg.length = 12;

    ret = ecall_encrypt_message(
        eid, &dec_ret,
        plaintext_out, 12,
        out_msg.iv,
        out_msg.ciphertext,
        out_msg.tag
    );

    if (ret != SGX_SUCCESS || dec_ret != SGX_SUCCESS) {
        printf("Encryption ECALL failed.\n");
        CloseHandle(hPipe);
        return 1;
    }

    // === Send response ===
    DWORD bytesWritten = 0;
    success = WriteFile(hPipe, &out_msg, sizeof(EncryptedMessage), &bytesWritten, NULL);
    if (!success || bytesWritten != sizeof(EncryptedMessage)) {
        printf("Failed to write response.\n");
        CloseHandle(hPipe);
        return 1;
    }

    printf("Response written successfully.\n");

    // Cleanup
    CloseHandle(hPipe);
    sgx_destroy_enclave(eid);
    printf("Enclave destroyed.\n");

    return 0;
}