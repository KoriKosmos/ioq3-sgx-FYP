#include "DevEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_calculate_damage_t {
	int ms_attackerId;
	int ms_targetId;
	int ms_baseDamage;
	int ms_weaponType;
	int* ms_finalDamage;
} ms_ecall_calculate_damage_t;

typedef struct ms_ecall_update_health_t {
	int ms_playerId;
	int ms_deltaHealth;
	const char* ms_sourceType;
	size_t ms_sourceType_len;
	int* ms_newHealth;
} ms_ecall_update_health_t;

typedef struct ms_ocall_log_t {
	const char* ms_message;
} ms_ocall_log_t;

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

static sgx_status_t SGX_CDECL DevEnclave_ocall_log(void* pms)
{
	ms_ocall_log_t* ms = SGX_CAST(ms_ocall_log_t*, pms);
	ocall_log(ms->ms_message);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DevEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DevEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DevEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DevEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL DevEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_DevEnclave = {
	6,
	{
		(void*)(uintptr_t)DevEnclave_ocall_log,
		(void*)(uintptr_t)DevEnclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)DevEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)DevEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)DevEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)DevEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ecall_calculate_damage(sgx_enclave_id_t eid, int attackerId, int targetId, int baseDamage, int weaponType, int* finalDamage)
{
	sgx_status_t status;
	ms_ecall_calculate_damage_t ms;
	ms.ms_attackerId = attackerId;
	ms.ms_targetId = targetId;
	ms.ms_baseDamage = baseDamage;
	ms.ms_weaponType = weaponType;
	ms.ms_finalDamage = finalDamage;
	status = sgx_ecall(eid, 0, &ocall_table_DevEnclave, &ms);
	return status;
}

sgx_status_t ecall_update_health(sgx_enclave_id_t eid, int playerId, int deltaHealth, const char* sourceType, int* newHealth)
{
	sgx_status_t status;
	ms_ecall_update_health_t ms;
	ms.ms_playerId = playerId;
	ms.ms_deltaHealth = deltaHealth;
	ms.ms_sourceType = sourceType;
	ms.ms_sourceType_len = sourceType ? strlen(sourceType) + 1 : 0;
	ms.ms_newHealth = newHealth;
	status = sgx_ecall(eid, 1, &ocall_table_DevEnclave, &ms);
	return status;
}

