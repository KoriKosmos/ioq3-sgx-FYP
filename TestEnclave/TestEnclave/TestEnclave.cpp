#include "TestEnclave_t.h"
#include "sgx_trts.h"
#include <cstring>

// Change input buffer with a constant string
void enclaveChangeBuffer(char* buf, size_t len) {
    const char* secret = "Hello from TestEnclave!";
    if (len > strlen(secret)) {
        memcpy(buf, secret, strlen(secret) + 1); // Copy the secret to the buffer
    }
    else {
        memcpy(buf, "false", strlen("false") + 1); // Indicate failure if buffer is too small
    }
}
