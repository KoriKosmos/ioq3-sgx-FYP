#include "sgx_interface.h"
#include "sgx_pipe_client.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Dummy encryption function – replace with your actual encryption logic (or call your ECALL wrapper)
static int EncryptBuffer(const uint8_t* inBuffer, uint32_t inLength, EncryptedMessage* outMsg) {
    // Here, we simply set a zero IV and copy the plaintext as ciphertext.
    memset(outMsg->iv, 0, sizeof(outMsg->iv));
    if (inLength > sizeof(outMsg->ciphertext)) {
        return -1;
    }
    memcpy(outMsg->ciphertext, inBuffer, inLength);
    // Set a dummy tag (all zeros) – replace with real MAC from AES-GCM in production.
    memset(outMsg->tag, 0, sizeof(outMsg->tag));
    outMsg->length = inLength;
    return 0;
}

// Dummy decryption function – replace with your actual decryption logic (or call your ECALL wrapper)
static int DecryptBuffer(const EncryptedMessage* inMsg, uint8_t* outBuffer, uint32_t expectedLength) {
    if (inMsg->length != expectedLength) {
        return -1;
    }
    memcpy(outBuffer, inMsg->ciphertext, expectedLength);
    return 0;
}

// SGX_ValidateDamage: This function takes a DamageInput structure, encrypts it,
// sends it via the pipe to the IOQ3IntegrationApp (which then talks to the enclave),
// and decrypts the returned DamageOutput.
int SGX_ValidateDamage(const DamageInput* input, DamageOutput* output) {
    // Serialize DamageInput into a buffer.
    uint8_t plainBuffer[sizeof(DamageInput)];
    memcpy(plainBuffer, input, sizeof(DamageInput));

    EncryptedMessage outMsg = { 0 };
    if (EncryptBuffer(plainBuffer, sizeof(DamageInput), &outMsg) != 0) {
        printf("SGX_ValidateDamage: Encryption failed.\n");
        return -1;
    }

    EncryptedMessage inMsg = { 0 };
    if (SGX_PipeTransfer(&outMsg, &inMsg) != 0) {
        printf("SGX_ValidateDamage: Pipe transfer failed.\n");
        return -1;
    }

    uint8_t decryptedBuffer[sizeof(DamageOutput)] = { 0 };
    if (DecryptBuffer(&inMsg, decryptedBuffer, sizeof(DamageOutput)) != 0) {
        printf("SGX_ValidateDamage: Decryption failed.\n");
        return -1;
    }

    memcpy(output, decryptedBuffer, sizeof(DamageOutput));
    return 0;
}
