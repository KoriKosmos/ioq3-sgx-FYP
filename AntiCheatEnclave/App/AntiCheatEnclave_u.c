#include "AntiCheatEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_keypair_t {
	sgx_status_t ms_retval;
} ms_ecall_generate_keypair_t;

typedef struct ms_ecall_get_public_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pub_key_x;
	uint8_t* ms_pub_key_y;
	size_t ms_len;
} ms_ecall_get_public_key_t;

typedef struct ms_ecall_validate_shot_t {
	int ms_attacker_id;
	int ms_target_id;
	int ms_weapon_type;
	int ms_hit_location;
	float ms_distance;
	int ms_damage;
	int* ms_is_valid;
} ms_ecall_validate_shot_t;

typedef struct ms_ecall_store_host_pubkey_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_host_pubkey_x;
	const uint8_t* ms_host_pubkey_y;
	size_t ms_len;
} ms_ecall_store_host_pubkey_t;

typedef struct ms_ecall_derive_shared_secret_t {
	sgx_status_t ms_retval;
} ms_ecall_derive_shared_secret_t;

typedef struct ms_ecall_encrypt_message_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_plaintext;
	size_t ms_msg_len;
	const uint8_t* ms_iv;
	uint8_t* ms_ciphertext;
	uint8_t* ms_mac;
} ms_ecall_encrypt_message_t;

typedef struct ms_ecall_decrypt_message_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_ciphertext;
	const uint8_t* ms_tag;
	const uint8_t* ms_iv;
	size_t ms_ct_len;
	size_t ms_tag_len;
	size_t ms_iv_len;
	uint8_t* ms_plaintext;
} ms_ecall_decrypt_message_t;

typedef struct ms_ecall_validate_damage_t {
	sgx_status_t ms_retval;
	int ms_damage;
	int ms_armor;
	int ms_dflags;
	int* ms_final_damage;
	int* ms_final_armor;
	int* ms_knockback;
} ms_ecall_validate_damage_t;

typedef struct ms_ocall_log_message_t {
	const char* ms_message;
} ms_ocall_log_message_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL AntiCheatEnclave_ocall_log_message(void* pms)
{
	ms_ocall_log_message_t* ms = SGX_CAST(ms_ocall_log_message_t*, pms);
	ocall_log_message(ms->ms_message);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL AntiCheatEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL AntiCheatEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL AntiCheatEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL AntiCheatEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL AntiCheatEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_AntiCheatEnclave = {
	6,
	{
		(void*)(uintptr_t)AntiCheatEnclave_ocall_log_message,
		(void*)(uintptr_t)AntiCheatEnclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)AntiCheatEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)AntiCheatEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)AntiCheatEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)AntiCheatEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ecall_generate_keypair(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_generate_keypair_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_AntiCheatEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_public_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* pub_key_x, uint8_t* pub_key_y, size_t len)
{
	sgx_status_t status;
	ms_ecall_get_public_key_t ms;
	ms.ms_pub_key_x = pub_key_x;
	ms.ms_pub_key_y = pub_key_y;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_AntiCheatEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_validate_shot(sgx_enclave_id_t eid, int attacker_id, int target_id, int weapon_type, int hit_location, float distance, int damage, int* is_valid)
{
	sgx_status_t status;
	ms_ecall_validate_shot_t ms;
	ms.ms_attacker_id = attacker_id;
	ms.ms_target_id = target_id;
	ms.ms_weapon_type = weapon_type;
	ms.ms_hit_location = hit_location;
	ms.ms_distance = distance;
	ms.ms_damage = damage;
	ms.ms_is_valid = is_valid;
	status = sgx_ecall(eid, 2, &ocall_table_AntiCheatEnclave, &ms);
	return status;
}

sgx_status_t ecall_store_host_pubkey(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* host_pubkey_x, const uint8_t* host_pubkey_y, size_t len)
{
	sgx_status_t status;
	ms_ecall_store_host_pubkey_t ms;
	ms.ms_host_pubkey_x = host_pubkey_x;
	ms.ms_host_pubkey_y = host_pubkey_y;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_AntiCheatEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_derive_shared_secret(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_derive_shared_secret_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_AntiCheatEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_encrypt_message(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* plaintext, size_t msg_len, const uint8_t* iv, uint8_t* ciphertext, uint8_t* mac)
{
	sgx_status_t status;
	ms_ecall_encrypt_message_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_msg_len = msg_len;
	ms.ms_iv = iv;
	ms.ms_ciphertext = ciphertext;
	ms.ms_mac = mac;
	status = sgx_ecall(eid, 5, &ocall_table_AntiCheatEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_decrypt_message(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* ciphertext, const uint8_t* tag, const uint8_t* iv, size_t ct_len, size_t tag_len, size_t iv_len, uint8_t* plaintext)
{
	sgx_status_t status;
	ms_ecall_decrypt_message_t ms;
	ms.ms_ciphertext = ciphertext;
	ms.ms_tag = tag;
	ms.ms_iv = iv;
	ms.ms_ct_len = ct_len;
	ms.ms_tag_len = tag_len;
	ms.ms_iv_len = iv_len;
	ms.ms_plaintext = plaintext;
	status = sgx_ecall(eid, 6, &ocall_table_AntiCheatEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_validate_damage(sgx_enclave_id_t eid, sgx_status_t* retval, int damage, int armor, int dflags, int* final_damage, int* final_armor, int* knockback)
{
	sgx_status_t status;
	ms_ecall_validate_damage_t ms;
	ms.ms_damage = damage;
	ms.ms_armor = armor;
	ms.ms_dflags = dflags;
	ms.ms_final_damage = final_damage;
	ms.ms_final_armor = final_armor;
	ms.ms_knockback = knockback;
	status = sgx_ecall(eid, 7, &ocall_table_AntiCheatEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

