/* taihen.c -- cfw framework for PS Vita
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include "error.h"
#include "module.h"
#include "patches.h"
#include "proc_map.h"
#include "taihen_internal.h"

/** @brief      The maximum length for a line in the config file. */
#define MAX_LINE_LEN 256

/**
 * @brief      Reads a line from the config.
 *
 * @param[out] line  The line
 *
 * @return     Actual number of characters read.
 */
static size_t read_line(char line[MAX_LINE_LEN]) {
  return 0;
}

/**
 * @brief      Loads plugins specified by the configuration.
 *
 *             By default, the config is at `ux0:tai/config.txt`. Each line of
 *             the config file is a command. Currently the only commands
 *             supported are
 *
 *             ``` hookuser path [module name] hookkern path ```
 *
 *             The way the `hookuser` command works is that whenever it string
 *             matches module name when a user module is loaded, it will load
 *             the plugin. If the module name is omitted, it will load with
 *             every application launch. The plugin will be unloaded when the
 *             application exits. It is also possible for multiple instances of
 *             the plugin to be loaded if it is hooked into multiple
 *             applications. For `hookkern`, the kernel plugin is loaded at the
 *             start of taiHEN and stays resident until it is manually unloaded
 *             by itself or another plugin. Any line in the config that starts
 *             with `#` will be ignored. This provides a quick way to turn off
 *             plugins. Each line must be at most `MAX_LINE_LEN` characters.
 *
 * @param[in]  path  Path to the config file
 *
 * @return     Zero for success SCE_KERNEL_ERROR code on IO error
 */
static int load_config(const char *path) {
  return 0;
}

/**
 * @brief      Add a hook given an absolute address
 *
 *             If target is the kernel, use KERNEL_PID as `pid`.
 *
 * @param[in]  pid        The pid of the target
 * @param[out] p_hook     A reference that can be used by the hook function
 * @param      dest_func  The function to patch (must be in the target address
 *                        space)
 * @param[in]  hook_func  The hook function (must be in the target address
 *                        space)
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiHookFunctionAbs(SceUID pid, tai_hook_ref_t *p_hook, void *dest_func, const void *hook_func) {
  return tai_hook_func_abs(p_hook, pid, dest_func, hook_func);
}

/**
 * @brief      Add a hook to a module function export
 *
 *             If target is the kernel, use KERNEL_PID as `pid`. Since a module
 *             can have two libraries that export the same NID, you can
 *             optionally pass in the library NID of the one to hook. Otherwise,
 *             use `TAI_ANY_LIBRARY` and the first one found will be used.
 *
 * @param[in]  pid          The pid of the target
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
SceUID taiHookFunctionExportForKernel(SceUID pid, tai_hook_ref_t *p_hook, const char *module, uint32_t library_nid, uint32_t func_nid, const void *hook_func) {
  int ret;
  uintptr_t func;

  ret = module_get_export_func(pid, module, library_nid, func_nid, &func);
  if (ret < 0) {
    LOG("Failed to find export for %s, NID:0x%08X: 0x%08X", module, func_nid, ret);
    return ret;
  }
  return taiHookFunctionAbs(pid, p_hook, (void *)func, hook_func);
}

/**
 * @brief      Add a hook to a module function import
 *
 *             If target is the kernel, use KERNEL_PID as `pid`. This will let
 *             you hook calls from one module to another without having to hook
 *             all calls to that module.
 *
 * @param[in]  pid                 The pid of the target
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
SceUID taiHookFunctionImportForKernel(SceUID pid, tai_hook_ref_t *p_hook, const char *module, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func) {
  int ret;
  uintptr_t stub;

  ret = module_get_import_func(pid, module, import_library_nid, import_func_nid, &stub);
  if (ret < 0) {
    LOG("Failed to find stub for %s, NID:0x%08X: 0x%08X", module, import_func_nid, ret);
    return ret;
  }
  return taiHookFunctionAbs(pid, p_hook, (void *)stub, hook_func);
}

/**
 * @brief      Add a hook to a module manually with an offset
 *
 *             If target is the kernel, use KERNEL_PID as `pid`. The caller is
 *             responsible for checking that the module is of the correct
 *             version!
 *
 * @param[in]  pid        The pid of the target
 * @param[out] p_hook     A reference that can be used by the hook function
 * @param[in]  modid      The module UID from `taiGetModuleInfoForKernel`
 * @param[in]  segidx     The ELF segment index containing the function to patch
 * @param[in]  offset     The offset from the start of the segment
 * @param[in]  thumb      Set to 1 if this is a Thumb function
 * @param[in]  hook_func  The hook function (must be in the target address
 *                        space)
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiHookFunctionOffsetForKernel(SceUID pid, tai_hook_ref_t *p_hook, SceUID modid, int segidx, uint32_t offset, int thumb, const void *hook_func) {
  int ret;
  uintptr_t addr;

  ret = module_get_offset(pid, modid, segidx, offset, &addr);
  if (ret < 0) {
    LOG("Failed to find offset for mod:%x, segidx:%d, offset:0x%08X: 0x%08X", modid, segidx, offset, ret);
    return ret;
  }
  if (thumb) {
    addr = addr | 1;
  }
  return taiHookFunctionAbs(pid, p_hook, (void *)addr, hook_func);
}

/**
 * @brief      Gets information on a currently loaded module
 *
 *             You should use this before calling
 *             `taiHookFunctionOffsetForKernel` in order to check that the
 *             module you wish to hook is currently loaded and that the module
 *             NID matches. The module NID changes in each version of the
 *             module.
 *
 * @param[in]  pid     The pid of the _caller_ (kernel should set to KERNEL_PID)
 * @param[in]  module  The name of the module
 * @param[out] info    The information to fill
 *
 * @return     Zero on success, < 0 on error
 */
int taiGetModuleInfoForKernel(SceUID pid, const char *module, tai_module_info_t *info) {
  return module_get_by_name_nid(pid, module, 0, info);
}

/**
 * @brief      Release a hook
 *
 * @param[in]  tai_uid  The tai patch reference to free
 * @param[in]  hook     The hook to free
 *
 * @return     Zero on success, < 0 on error
 */
int taiHookReleaseForKernel(SceUID tai_uid, tai_hook_ref_t hook) {
  return tai_hook_release(tai_uid, hook);
}

/**
 * @brief      Injects data into a process bypassing MMU flags
 *
 * @param[in]  pid   The pid of the target (can be KERNEL_PID)
 * @param      dest  The destination in the process address space
 * @param[in]  src   The source in kernel address space
 * @param[in]  size  The size of the injection in bytes
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiInjectAbsForKernel(SceUID pid, void *dest, const void *src, size_t size) {
  return tai_inject_abs(pid, dest, src, size);
}

/**
 * @brief      Inject data into a process bypassing MMU flags given an offset
 *
 * @param[in]  pid     The pid of the target (can be KERNEL_PID)
 * @param[in]  modid   The module UID from `taiGetModuleInfoForKernel`
 * @param[in]  segidx  Index of the ELF segment containing the data to patch
 * @param[in]  offset  The offset from the start of the segment
 * @param[in]  data    The data in kernel address space
 * @param[in]  size    The size of the injection in bytes
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiInjectDataForKernel(SceUID pid, SceUID modid, int segidx, uint32_t offset, const void *data, size_t size) {
  int ret;
  uintptr_t addr;

  ret = module_get_offset(pid, modid, segidx, offset, &addr);
  if (ret < 0) {
    LOG("Failed to find offset for mod:%x, segidx:%d, offset:0x%08X: 0x%08X", modid, segidx, offset, ret);
    return ret;
  }
  return taiInjectAbsForKernel(pid, (void *)addr, data, size);
}

/**
 * @brief      Release an injection
 *
 * @param[in]  tai_uid  The tai patch reference to free
 *
 * @return     Zero on success, < 0 on error
 */
int taiInjectReleaseForKernel(SceUID tai_uid) {
  return tai_inject_release(tai_uid);
}

/**
 * @brief      Module entry point
 *
 *             This module should be loaded by a kernel exploit. taiHEN expects
 *             the kernel environment to be clean, which means that no outside
 *             hooks and patches which may interfere with taiHEN.
 *
 * @param[in]  argc  Size of arguments (unused)
 * @param[in]  args  The arguments (unused)
 *
 * @return     Success always
 */
int module_start(SceSize argc, const void *args) {
  return 0;
}

/**
 * @brief      Module cleanup
 *
 *             This cleans up the system and removes all hooks and patches. All
 *             handles held by plugins will be invalid after this point! This is
 *             called by the kernel module manager. In usual operation, you
 *             should not unload taiHEN.
 *
 * @param[in]  argc  Size of arguments (unused)
 * @param[in]  args  The arguments (unused)
 *
 * @return     Success always
 */
int module_stop(SceSize argc, const void *args) {
  return 0;
}

/**
 * @brief      Module Exit handler (unused)
 *
 *             This function is currently unused on retail units.
 */
void module_exit(void) {

}
