/* taihen-user.c -- user exports for taiHEN
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2/kernel/error.h>
#include "module.h"
#include "patches.h"
#include "taihen_internal.h"

/**
 * @brief      Add a hook to a module function export for the calling process
 *
 * @see        taiHookFunctionExportForKernel
 *
 * @param[out] p_hook       A reference that can be used by the hook function
 * @param[in]  module       Name of the target module.
 * @param[in]  library_nid  Optional. NID of the target library.
 * @param[in]  func_nid     The function NID. If `library_nid` is 0, then the
 *                          first export with the NID will be hooked.
 * @param[in]  hook_func    The hook function (must be in the target address
 *                          space)
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiHookFunctionExport(tai_hook_ref_t **p_hook, const char *module, uint32_t library_nid, uint32_t func_nid, const void *hook_func) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Add a hook to a module function import for the calling process
 *
 * @see        taiHookFunctionImportForKernel
 *
 * @param[out] p_hook              A reference that can be used by the hook
 *                                 function
 * @param[in]  module              Name of the target module.
 * @param[in]  import_library_nid  The imported library from the target module
 * @param[in]  import_func_nid     The function NID of the import
 * @param[in]  hook_func           The hook function (must be in the target
 *                                 address space)
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiHookFunctionImport(tai_hook_ref_t **p_hook, const char *module, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Add a hook to a module manually with an offset for the calling
 *             process
 *
 * @see        taiHookFunctionOffsetForKernel
 *
 * @param[out] p_hook     A reference that can be used by the hook function
 * @param[in]  modid      The module UID from `taiGetModuleInfo`
 * @param[in]  segidx     The ELF segment index containing the function to patch
 * @param[in]  offset     The offset from the start of the segment
 * @param[in]  thumb      Set to 1 if this is a Thumb function
 * @param[in]  hook_func  The hook function (must be in the target address
 *                        space)
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiHookFunctionOffset(tai_hook_ref_t **p_hook, SceUID modid, int segidx, uint32_t offset, int thumb, const void *hook_func) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Gets information on a currently loaded module
 *
 * @see        taiGetModuleInfoForKernel
 *
 * @param[in]  module  The name of the module
 * @param[out] info    The information to fill
 *
 * @return     Zero on success, < 0 on error
 */
int taiGetModuleInfo(const char *module, tai_module_info_t *info) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Release a hook or injection for the calling process
 *
 * @see        taiReleaseForKernel
 *
 * @param[in]  tai_uid  The tai patch reference to free
 *
 * @return     Zero on success, < 0 on error
 */
int taiRelease(SceUID tai_uid) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Injects data into the current process bypassing MMU flags
 * 
 * @see taiInjectAbsForKernel
 *
 * @param      dest  The address to inject
 * @param[in]  src   Source data
 * @param[in]  size  The size of the injection in bytes
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiInjectAbs(void *dest, const void *src, size_t size) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Inject data into the current process bypassing MMU flags given an
 *             offset
 *
 * @see        taiInjectDataForKernel
 *
 * @param[in]  module  Name of the target module.
 * @param[in]  segidx  Index of the ELF segment containing the data to patch
 * @param[in]  offset  The offset from the start of the segment
 * @param[in]  data    Source data
 * @param[in]  size    The size of the injection in bytes
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiInjectData(const char *module, int segidx, uint32_t offset, const void *data, size_t size) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Loads a kernel module
 *
 * @param[in]  path   The path to the skprx
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 *
 * @return     A module reference on success, < 0 on error
 */
SceUID taiLoadKernelModule(const char *path, int flags, int *opt) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Starts a kernel module
 *
 * @param[in]  modid  The id from `taiLoadKernelModule`
 * @param[in]  argc   The size of the arguments
 * @param      args   The arguments
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_start`
 *
 * @return     Zero on success, < 0 on error
 */
int taiStartKernelModule(SceUID modid, int argc, void *args, int flags, void *opt, int *res) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Loads and starts a kernel module
 *
 * @param[in]  path   The path of the skprx
 * @param[in]  argc   The size of the arguments
 * @param      args   The arguments
 * @param[in]  flags  The flags
 *
 * @return     A module reference on success, < 0 on error
 */
SceUID taiLoadStartKernelModule(const char *path, int argc, void *args, int flags) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Stops and unloads a kernel module
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  argc   The size of the arguments to `module_stop`
 * @param      args   The arguments to `module_stop`
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 *
 * @return     Zero on success, < 0 on error
 */
int taiStopUnloadKernelModule(SceUID modid, int argc, void *args, int flags, void *opt, int *res) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Unloads a kernel module directly
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  flags  The flags
 *
 * @return     Zero on success, < 0 on error
 */
int taiUnloadKernelModule(SceUID modid, int flags) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Copies data from user to kernel
 *
 * @param      kernel_dst  The kernel address
 * @param[in]  user_src    The user address
 * @param[in]  len         The length
 *
 * @return     Zero on success, < 0 on error
 */
int taiMemcpyUserToKernel(void *kernel_dst, const void *user_src, size_t len) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief      Copies data from kernel to user
 *
 *             Does not bypass the MMU!
 *
 * @see        taiInjectData
 *
 * @param      user_dst    The user address
 * @param[in]  kernel_src  The kernel address
 * @param[in]  len         The length
 *
 * @return     Zero on success, < 0 on error
 */
int taiMemcpyKernelToUser(void *user_dst, const void *kernel_src, size_t len) {
  return SCE_KERNEL_ERROR_NOT_IMPLEMENTED;
}
