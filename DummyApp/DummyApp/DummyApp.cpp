#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define PIPE_NAME TEXT("\\\\.\\pipe\\IoQ3SecurePipe")

// Match structure from enclave_ipc.h
typedef struct EncryptedMessage {
    uint8_t iv[12];
    uint8_t ciphertext[128];
    uint8_t tag[16];
    uint32_t length;
} EncryptedMessage;

int main() {
    printf("Connecting to named pipe...\n");

    HANDLE hPipe = CreateFile(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Failed to connect to pipe. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("Connected to pipe.\n");

    // === Dummy Payload ===
    int damage = 50;
    int armor = 25;
    int dflags = 1;

    uint8_t plaintext[12] = { 0 };
    memcpy(&plaintext[0], &damage, sizeof(int));
    memcpy(&plaintext[4], &armor, sizeof(int));
    memcpy(&plaintext[8], &dflags, sizeof(int));

    // === Dummy Encryption (no real AES-GCM yet) ===
    EncryptedMessage msg = { 0 };
    memcpy(msg.iv, "fake_iv_1234", 12);                      // Dummy IV
    memcpy(msg.ciphertext, plaintext, 12);                   // Pretend "encrypted"
    memset(msg.tag, 0xAB, sizeof(msg.tag));                  // Dummy MAC tag
    msg.length = 12;

    DWORD bytesWritten = 0;
    BOOL success = WriteFile(hPipe, &msg, sizeof(msg), &bytesWritten, NULL);
    if (!success || bytesWritten != sizeof(msg)) {
        printf("Failed to write to pipe. Error: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("Sent dummy EncryptedMessage to enclave server.\n");

    // === Receive response ===
    EncryptedMessage response = { 0 };
    DWORD bytesRead = 0;
    success = ReadFile(hPipe, &response, sizeof(response), &bytesRead, NULL);
    if (!success || bytesRead != sizeof(response)) {
        printf("Failed to read from pipe. Error: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("Received EncryptedMessage from enclave server.\n");

    // === Fake decryption ===
    int out_damage = 0, out_armor = 0, out_knockback = 0;
    memcpy(&out_damage, &response.ciphertext[0], sizeof(int));
    memcpy(&out_armor, &response.ciphertext[4], sizeof(int));
    memcpy(&out_knockback, &response.ciphertext[8], sizeof(int));

    printf("Final Damage: %d\n", out_damage);
    printf("Armor Absorbed: %d\n", out_armor);
    printf("Knockback: %d\n", out_knockback);

    CloseHandle(hPipe);
    return 0;
}
