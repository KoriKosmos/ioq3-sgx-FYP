#ifndef SGX_PIPE_CLIENT_H
#define SGX_PIPE_CLIENT_H

#include "enclave_ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

	// SGX_PipeTransfer transfers an EncryptedMessage over the pipe and receives the reply.
	// Returns 0 on success, nonzero on failure.
	int SGX_PipeTransfer(const EncryptedMessage* outMsg, EncryptedMessage* inMsg);

#ifdef __cplusplus
}
#endif

#endif // SGX_PIPE_CLIENT_H
