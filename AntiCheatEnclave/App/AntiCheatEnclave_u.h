#ifndef ANTICHEATENCLAVE_U_H__
#define ANTICHEATENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_LOG_MESSAGE_DEFINED__
#define OCALL_LOG_MESSAGE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_log_message, (const char* message));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_generate_keypair(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_get_public_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* pub_key_x, uint8_t* pub_key_y, size_t len);
sgx_status_t ecall_validate_shot(sgx_enclave_id_t eid, int attacker_id, int target_id, int weapon_type, int hit_location, float distance, int damage, int* is_valid);
sgx_status_t ecall_store_host_pubkey(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* host_pubkey_x, const uint8_t* host_pubkey_y, size_t len);
sgx_status_t ecall_derive_shared_secret(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_encrypt_message(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* plaintext, size_t msg_len, const uint8_t* iv, uint8_t* ciphertext, uint8_t* mac);
sgx_status_t ecall_decrypt_message(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* ciphertext, const uint8_t* tag, const uint8_t* iv, size_t ct_len, size_t tag_len, size_t iv_len, uint8_t* plaintext);
sgx_status_t ecall_validate_damage(sgx_enclave_id_t eid, sgx_status_t* retval, int damage, int armor, int dflags, int* final_damage, int* final_armor, int* knockback);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
