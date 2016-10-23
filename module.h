/**
 * @brief      NID lookup system
 */
#ifndef TAI_MODULE_HEADER
#define TAI_MODULE_HEADER

#include "taihen_internal.h"

/**
 * @defgroup   module NID Lookup Interface
 */
/** @{ */

int module_get_by_name_nid(SceUID pid, const char *name, uint32_t nid, tai_module_info_t *info);
int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);
int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);
int module_get_import_func(SceUID pid, const char *modname, uint32_t target_libnid, uint32_t funcnid, uintptr_t *stub);

/** @} */

#endif // TAI_MODULE_HEADER
