// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Stubs for symbols that libservtd_attest_app.a references but that the
// `verify_quote_integrity_ex()` code path does not actually invoke. Without
// these, the linker fails with `undefined reference to servtd_get_quote`.
//
// `servtd_get_quote` is the caller-supplied quote-fetch callback used by the
// quote-generation paths. We do not exercise quote generation in this
// reproducer (we feed a pre-captured quote in), so a stub that always returns
// failure is sufficient.
//
// `sgx_read_rand`, `mm_commit`, `mm_uncommit` are already provided by
// `servtd_utils.o` inside `libservtd_attest_app.a`; we do not need to
// redefine them here.
//
// Under the `bounded-heap` feature (VQR_BOUNDED_HEAP):
//   1. We strip `libservtd_attest_extras.o` from the archive (to avoid
//      clashing `heap_base`/`heap_size` defs against tlibc's real `sbrk.o`),
//      and re-supply our own `__errno()` forwarder to glibc here.
//   2. The QvE/PCK-parser C++ objects we link in carry static initializers
//      (`_GLOBAL__sub_I_qve.cpp` etc.) that run before `main()` via
//      `.init_array`. Those initializers allocate via tlibc's dlmalloc, but
//      `heap_base` is still NULL — so the first `malloc()` returns NULL and
//      the C++ runtime traps (`#UD`). In the actual MigTD payload this is
//      a non-issue because the binary is no_std + no glibc-style startup —
//      no `.init_array` walker. To match that semantics on the host we
//      pre-init the heap with a generous static buffer from a high-priority
//      constructor; the harness can then re-arm the heap at runtime to a
//      smaller bound (via `vqr_reset_heap()`) to study the high-water mark.

#include <stdint.h>
#include <stddef.h>

int servtd_get_quote(const void* p_get_quote_blob, uint64_t len) {
    (void)p_get_quote_blob;
    (void)len;
    return -1;
}

#ifdef VQR_BOUNDED_HEAP

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timeb.h>

int* __errno(void) {
    extern int* __errno_location(void);
    return __errno_location();
}

// sgx_read_rand: tlibc's bounded dlmalloc calls this for its magic seed.
// The upstream impl (linux-sgx/common/src/sgx_read_rand.cpp) does an
// Intel-vendor cpuid check and returns SGX_ERROR_UNEXPECTED on AMD, which
// makes dlmalloc's init_mparams() ABORT on the very first malloc on AMD
// hosts. Override with a glibc rand()-backed implementation: weak in
// quality but adequate for the dlmalloc magic seed.
typedef int sgx_status_t;
#define VQR_SGX_SUCCESS 0
sgx_status_t sgx_read_rand(unsigned char* buf, size_t size) {
    if (!buf) return -1;
    for (size_t i = 0; i < size; i++) buf[i] = (unsigned char)(rand() & 0xff);
    return VQR_SGX_SUCCESS;
}

// SgxSSL OCALL: normally provided by the enclave's host application via the
// SGX OCALL bridge. We are not in an enclave; just fill the timeb struct
// from host gettimeofday(). Used by OpenSSL time-based code paths (cert
// validity checks, etc.).
sgx_status_t u_sgxssl_ftime(void* timeptr, uint32_t timeb_len) {
    if (!timeptr || timeb_len < sizeof(struct timeb)) return -1;
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return -1;
    struct timeb tb = {0};
    tb.time = tv.tv_sec;
    tb.millitm = (unsigned short)(tv.tv_usec / 1000);
    memcpy(timeptr, &tb, sizeof(tb));
    return VQR_SGX_SUCCESS;
}

// 16 MiB static buffer used to pre-arm tlibc's heap before the C++ static
// initializers (`_GLOBAL__sub_I_qve.cpp` and friends) run via .init_array.
// Without this they call malloc() with heap_base == NULL and the C++ runtime
// aborts. Page-aligned per heap_init's requirement.
#define VQR_EARLY_HEAP_SIZE (16u * 1024u * 1024u)
static unsigned char __attribute__((aligned(0x1000)))
    vqr_early_heap[VQR_EARLY_HEAP_SIZE];

extern int init_heap(const void* p_td_heap_base, uint32_t td_heap_size);

// Priority 101 = just past the 0..100 system-reserved band; fires before any
// of the C++ static-init ctors (which are emitted without an explicit
// priority and therefore live in the default group).
__attribute__((constructor(101)))
static void vqr_early_init_heap(void) {
    (void)init_heap((const void*)vqr_early_heap, VQR_EARLY_HEAP_SIZE);
}

extern void* heap_base;
extern size_t heap_size;
extern size_t g_peak_heap_used;

const void* vqr_static_heap_base(void) { return vqr_early_heap; }
size_t vqr_static_heap_size(void) { return VQR_EARLY_HEAP_SIZE; }

#endif
