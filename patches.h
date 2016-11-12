/**
 * @brief      Main patch system
 */
#ifndef TAI_PATCHES_HEADER
#define TAI_PATCHES_HEADER

#include "taihen_internal.h"

/**
 * @defgroup   patches Patch System
 * @brief      Modify read-only and executable memory
 *
 * @details    There are two kinds of patches. Injections are raw modifications
 *             to any memory address (including read-only) memory. Once an
 *             injection is inserted, nobody else can inject that memory address
 *             for that process. The original data is saved and when the
 *             injection is released, the it is written back. Hooks are handled
 *             by [substitute](http://github.com/comex/substitute) and one
 *             function can have multiple hooks chained together. This allows
 *             many plugins to hook the same function. Function hooks allow the
 *             plugin to run any code before and after a function is called.
 */
/** @{ */

int patches_init(void);
void patches_deinit(void);

void cache_flush(SceUID pid, uintptr_t vma, size_t len);
int tai_memcpy_to_kernel(SceUID src_pid, void *dst, const char *src, size_t size);
SceUID tai_hook_func_abs(tai_hook_ref_t *p_hook, SceUID pid, void *dest_func, const void *hook_func);
int tai_hook_release(SceUID uid, tai_hook_ref_t hook_ref);
SceUID tai_inject_abs(SceUID pid, void *dest, const void *src, size_t size);
int tai_inject_release(SceUID uid);
int tai_try_cleanup_process(SceUID pid);

/** @} */

#endif // TAI_PATCHES_HEADER
