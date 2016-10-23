/**
 * @brief      Main patch system
 */
#ifndef TAI_PATCHES_HEADER
#define TAI_PATCHES_HEADER

#include "taihen_internal.h"

/**
 * @defgroup   patches Patches Interface
 */
/** @{ */

int patches_init(void);
void patches_deinit(void);


SceUID tai_hook_func_abs(tai_hook_ref_t *p_hook, SceUID pid, void *dest_func, const void *hook_func);
int tai_hook_release(SceUID uid, tai_hook_ref_t hook_ref);
SceUID tai_inject_abs(SceUID pid, void *dest, const void *src, size_t size);
int tai_inject_release(SceUID uid);
int tai_try_cleanup_process(SceUID pid);

/** @} */

#endif // TAI_PATCHES_HEADER
