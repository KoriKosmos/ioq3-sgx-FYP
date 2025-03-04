#ifndef SGX_INTERFACE_H
#define SGX_INTERFACE_H

#include <stdint.h>
#include "enclave_ipc.h"  // Contains definitions for EncryptedMessage, DamageInput, DamageOutput

#ifdef __cplusplus
extern "C" {
#endif

	// SGX_ValidateDamage sends the DamageInput to the SGX anticheat process and returns the secure DamageOutput.
	// Returns 0 on success, nonzero on failure.
	int SGX_ValidateDamage(const struct DamageInput* input, struct DamageOutput* output);

#ifdef __cplusplus
}
#endif

#endif // SGX_INTERFACE_H
