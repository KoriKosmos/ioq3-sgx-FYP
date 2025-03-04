#include <windows.h>
#include <stdio.h>
#include "sgx_pipe_client.h"

#define PIPE_NAME TEXT("\\\\.\\pipe\\IoQ3SecurePipe")

// Helper: Open the named pipe.
static HANDLE OpenSgxPipe(void) {
    HANDLE hPipe = CreateFile(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    return hPipe;
}

// Transfers outMsg over the pipe and reads the reply into inMsg.
int SGX_PipeTransfer(const EncryptedMessage* outMsg, EncryptedMessage* inMsg) {
    HANDLE hPipe = OpenSgxPipe();
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("SGX_PipeTransfer: Failed to open pipe (error %d).\n", GetLastError());
        return -1;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hPipe, outMsg, sizeof(EncryptedMessage), &bytesWritten, NULL) ||
        bytesWritten != sizeof(EncryptedMessage)) {
        printf("SGX_PipeTransfer: WriteFile failed (error %d).\n", GetLastError());
        CloseHandle(hPipe);
        return -1;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hPipe, inMsg, sizeof(EncryptedMessage), &bytesRead, NULL) ||
        bytesRead != sizeof(EncryptedMessage)) {
        printf("SGX_PipeTransfer: ReadFile failed (error %d).\n", GetLastError());
        CloseHandle(hPipe);
        return -1;
    }

    CloseHandle(hPipe);
    return 0;
}
