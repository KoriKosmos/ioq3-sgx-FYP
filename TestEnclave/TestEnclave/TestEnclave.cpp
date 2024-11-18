#include "TestEnclave_t.h"
#include "sgx_trts.h"

// Generate a random number
void ecall_generate_random(uint32_t* random_number) {
    if (sgx_read_rand((unsigned char*)random_number, sizeof(uint32_t)) != SGX_SUCCESS) {
        *random_number = 0; // Default to 0 if random generation fails
    }
}
