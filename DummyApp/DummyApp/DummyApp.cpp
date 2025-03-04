#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "enclave_ipc.h"  // Ensure this file is in your include path

// Make sure this PIPE_NAME matches the one defined on the server side.
#define PIPE_NAME TEXT("\\\\.\\pipe\\IoQ3SecurePipe")

int main(void) {
    HANDLE hPipe;
    DWORD bytesWritten, bytesRead;

    // Attempt to open the named pipe.
    hPipe = CreateFile(
        PIPE_NAME,             // pipe name
        GENERIC_READ | GENERIC_WRITE, // read and write access
        0,                     // no sharing 
        NULL,                  // default security attributes
        OPEN_EXISTING,         // opens existing pipe
        0,                     // default attributes
        NULL                   // no template file
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("Failed to open pipe. Error: %lu\n", err);
        system("pause");
        return 1;
    }

    printf("Pipe connected.\n");

    // Prepare a dummy EncryptedMessage to send.
    EncryptedMessage outMsg;
    memset(&outMsg, 0, sizeof(outMsg)); // clear the structure

    // Fill dummy data:
    memset(outMsg.iv, 0x11, sizeof(outMsg.iv));             // dummy IV
    memset(outMsg.ciphertext, 0x22, sizeof(outMsg.ciphertext)); // dummy ciphertext
    memset(outMsg.tag, 0x33, sizeof(outMsg.tag));             // dummy tag
    outMsg.length = sizeof(outMsg.ciphertext);                // dummy length value

    // Send the dummy message over the pipe.
    if (!WriteFile(hPipe, &outMsg, sizeof(EncryptedMessage), &bytesWritten, NULL)) {
        printf("WriteFile failed. Error: %lu\n", GetLastError());
        CloseHandle(hPipe);
        system("pause");
        return 1;
    }
    printf("Dummy data sent. Bytes written: %lu\n", bytesWritten);

    // Wait for and read the response from the pipe.
    EncryptedMessage inMsg;
    memset(&inMsg, 0, sizeof(inMsg));
    if (!ReadFile(hPipe, &inMsg, sizeof(EncryptedMessage), &bytesRead, NULL)) {
        printf("ReadFile failed. Error: %lu\n", GetLastError());
        CloseHandle(hPipe);
        system("pause");
        return 1;
    }
    printf("Response received. Bytes read: %lu\n", bytesRead);

    // Dump a few bytes from the response for verification.
    printf("Response IV: ");
    for (int i = 0; i < sizeof(inMsg.iv); i++) {
        printf("%02X ", inMsg.iv[i]);
    }
    printf("\n");

    // Clean up and close the handle.
    CloseHandle(hPipe);
    printf("Pipe closed.\n");

    system("pause");
    return 0;
}
