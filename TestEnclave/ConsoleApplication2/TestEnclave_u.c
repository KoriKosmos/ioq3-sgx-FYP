#include "TestEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_calculate_damage_t {
	int ms_body_part;
	int* ms_damage;
} ms_ecall_calculate_damage_t;

typedef struct ms_ecall_consume_potion_t {
	int ms_potion_type;
	int* ms_health;
} ms_ecall_consume_potion_t;

typedef struct ms_ocall_log_message_t {
	const char* ms_message;
} ms_ocall_log_message_t;

typedef struct ms_ocall_get_random_seed_t {
	int ms_retval;
} ms_ocall_get_random_seed_t;

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

static sgx_status_t SGX_CDECL TestEnclave_ocall_log_message(void* pms)
{
	ms_ocall_log_message_t* ms = SGX_CAST(ms_ocall_log_message_t*, pms);
	ocall_log_message(ms->ms_message);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_ocall_get_random_seed(void* pms)
{
	ms_ocall_get_random_seed_t* ms = SGX_CAST(ms_ocall_get_random_seed_t*, pms);
	ms->ms_retval = ocall_get_random_seed();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[7];
} ocall_table_TestEnclave = {
	7,
	{
		(void*)(uintptr_t)TestEnclave_ocall_log_message,
		(void*)(uintptr_t)TestEnclave_ocall_get_random_seed,
		(void*)(uintptr_t)TestEnclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)TestEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)TestEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)TestEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ecall_calculate_damage(sgx_enclave_id_t eid, int body_part, int* damage)
{
	sgx_status_t status;
	ms_ecall_calculate_damage_t ms;
	ms.ms_body_part = body_part;
	ms.ms_damage = damage;
	status = sgx_ecall(eid, 0, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t ecall_consume_potion(sgx_enclave_id_t eid, int potion_type, int* health)
{
	sgx_status_t status;
	ms_ecall_consume_potion_t ms;
	ms.ms_potion_type = potion_type;
	ms.ms_health = health;
	status = sgx_ecall(eid, 1, &ocall_table_TestEnclave, &ms);
	return status;
}

