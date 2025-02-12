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

