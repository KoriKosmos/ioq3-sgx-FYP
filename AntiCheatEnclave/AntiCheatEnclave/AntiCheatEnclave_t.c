#include "AntiCheatEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#pragma warning(disable: 4090)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_generate_keypair(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_keypair_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_keypair_t* ms = SGX_CAST(ms_ecall_generate_keypair_t*, pms);
	ms_ecall_generate_keypair_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_keypair_t), ms, sizeof(ms_ecall_generate_keypair_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_generate_keypair();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_public_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_public_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_public_key_t* ms = SGX_CAST(ms_ecall_get_public_key_t*, pms);
	ms_ecall_get_public_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_public_key_t), ms, sizeof(ms_ecall_get_public_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_pub_key_x = __in_ms.ms_pub_key_x;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_pub_key_x = _tmp_len;
	uint8_t* _in_pub_key_x = NULL;
	uint8_t* _tmp_pub_key_y = __in_ms.ms_pub_key_y;
	size_t _len_pub_key_y = _tmp_len;
	uint8_t* _in_pub_key_y = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_pub_key_x, _len_pub_key_x);
	CHECK_UNIQUE_POINTER(_tmp_pub_key_y, _len_pub_key_y);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pub_key_x != NULL && _len_pub_key_x != 0) {
		if ( _len_pub_key_x % sizeof(*_tmp_pub_key_x) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pub_key_x = (uint8_t*)malloc(_len_pub_key_x)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pub_key_x, 0, _len_pub_key_x);
	}
	if (_tmp_pub_key_y != NULL && _len_pub_key_y != 0) {
		if ( _len_pub_key_y % sizeof(*_tmp_pub_key_y) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pub_key_y = (uint8_t*)malloc(_len_pub_key_y)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pub_key_y, 0, _len_pub_key_y);
	}
	_in_retval = ecall_get_public_key(_in_pub_key_x, _in_pub_key_y, _tmp_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_pub_key_x) {
		if (memcpy_verw_s(_tmp_pub_key_x, _len_pub_key_x, _in_pub_key_x, _len_pub_key_x)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pub_key_y) {
		if (memcpy_verw_s(_tmp_pub_key_y, _len_pub_key_y, _in_pub_key_y, _len_pub_key_y)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pub_key_x) free(_in_pub_key_x);
	if (_in_pub_key_y) free(_in_pub_key_y);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_validate_shot(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_validate_shot_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_validate_shot_t* ms = SGX_CAST(ms_ecall_validate_shot_t*, pms);
	ms_ecall_validate_shot_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_validate_shot_t), ms, sizeof(ms_ecall_validate_shot_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_is_valid = __in_ms.ms_is_valid;
	size_t _len_is_valid = sizeof(int);
	int* _in_is_valid = NULL;

	CHECK_UNIQUE_POINTER(_tmp_is_valid, _len_is_valid);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_is_valid != NULL && _len_is_valid != 0) {
		if ( _len_is_valid % sizeof(*_tmp_is_valid) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_is_valid = (int*)malloc(_len_is_valid)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_is_valid, 0, _len_is_valid);
	}
	ecall_validate_shot(__in_ms.ms_attacker_id, __in_ms.ms_target_id, __in_ms.ms_weapon_type, __in_ms.ms_hit_location, __in_ms.ms_distance, __in_ms.ms_damage, _in_is_valid);
	if (_in_is_valid) {
		if (memcpy_verw_s(_tmp_is_valid, _len_is_valid, _in_is_valid, _len_is_valid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_is_valid) free(_in_is_valid);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_store_host_pubkey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_store_host_pubkey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_store_host_pubkey_t* ms = SGX_CAST(ms_ecall_store_host_pubkey_t*, pms);
	ms_ecall_store_host_pubkey_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_store_host_pubkey_t), ms, sizeof(ms_ecall_store_host_pubkey_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_host_pubkey_x = __in_ms.ms_host_pubkey_x;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_host_pubkey_x = _tmp_len;
	uint8_t* _in_host_pubkey_x = NULL;
	const uint8_t* _tmp_host_pubkey_y = __in_ms.ms_host_pubkey_y;
	size_t _len_host_pubkey_y = _tmp_len;
	uint8_t* _in_host_pubkey_y = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_host_pubkey_x, _len_host_pubkey_x);
	CHECK_UNIQUE_POINTER(_tmp_host_pubkey_y, _len_host_pubkey_y);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_host_pubkey_x != NULL && _len_host_pubkey_x != 0) {
		if ( _len_host_pubkey_x % sizeof(*_tmp_host_pubkey_x) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_host_pubkey_x = (uint8_t*)malloc(_len_host_pubkey_x);
		if (_in_host_pubkey_x == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_host_pubkey_x, _len_host_pubkey_x, _tmp_host_pubkey_x, _len_host_pubkey_x)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_host_pubkey_y != NULL && _len_host_pubkey_y != 0) {
		if ( _len_host_pubkey_y % sizeof(*_tmp_host_pubkey_y) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_host_pubkey_y = (uint8_t*)malloc(_len_host_pubkey_y);
		if (_in_host_pubkey_y == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_host_pubkey_y, _len_host_pubkey_y, _tmp_host_pubkey_y, _len_host_pubkey_y)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_store_host_pubkey((const uint8_t*)_in_host_pubkey_x, (const uint8_t*)_in_host_pubkey_y, _tmp_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_host_pubkey_x) free(_in_host_pubkey_x);
	if (_in_host_pubkey_y) free(_in_host_pubkey_y);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_keypair, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_public_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_validate_shot, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_store_host_pubkey, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][4];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_log_message(const char* message)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = message ? strlen(message) + 1 : 0;

	ms_ocall_log_message_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_log_message_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(message, _len_message);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (message != NULL) ? _len_message : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_log_message_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_log_message_t));
	ocalloc_size -= sizeof(ms_ocall_log_message_t);

	if (message != NULL) {
		if (memcpy_verw_s(&ms->ms_message, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_message % sizeof(*message) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, message, _len_message)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_message);
		ocalloc_size -= _len_message;
	} else {
		ms->ms_message = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
