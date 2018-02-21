/* taihen.c -- cfw framework for PS Vita
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/ctrl.h>
#include <psp2kern/sblaimgr.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <taihen/parser.h>
#include "error.h"
#include "hen.h"
#include "module.h"
#include "patches.h"
#include "plugin.h"
#include "proc_map.h"
#include "taihen_internal.h"

/** For ordering log entries */
unsigned char log_ctr = 0;

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
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to hook
 *             - TAI_ERROR_INVALID_KERNEL_ADDR if `pid` is kernel and address is in shared memory region
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
 * @param[in]  func_nid     The function NID. If `library_nid` is
 *                          `TAI_ANY_LIBRARY`, then the first export with the
 *                          NID will be hooked.
 * @param[in]  hook_func    The hook function (must be in the target address
 *                          space)
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to
 *               hook
 *             - TAI_ERROR_INVALID_KERNEL_ADDR if `pid` is kernel and address is
 *               in shared memory region
 *             - TAI_ERROR_INVALID_MODULE if `module` is `TAI_MAIN_MODULE`
 *               and `pid` is kernel
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
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to
 *               hook
 *             - TAI_ERROR_INVALID_KERNEL_ADDR if `pid` is kernel and address is
 *               in shared memory region
 *             - TAI_ERROR_STUB_NOT_RESOLVED if the import has not been resolved
 *               yet. You should hook `sceKernelLoadStartModule`,
 *               `sceSysmoduleLoadModule` or whatever the application uses to
 *               start the imported module and add this hook after the module is
 *               loaded. Be sure to also hook module unloading to remove the
 *               hook BEFORE the imported module is unloaded!
 *             - TAI_ERROR_INVALID_MODULE if `module` is `TAI_MAIN_MODULE`
 *               and `pid` is kernel
 */
SceUID taiHookFunctionImportForKernel(SceUID pid, tai_hook_ref_t *p_hook, const char *module, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func) {
  int ret;
  uintptr_t stubptr;
  uint32_t stub[3];

  ret = module_get_import_func(pid, module, import_library_nid, import_func_nid, &stubptr);
  if (ret < 0) {
    LOG("Failed to find stub for %s, NID:0x%08X: 0x%08X", module, import_func_nid, ret);
    return ret;
  }
  ret = tai_memcpy_to_kernel(pid, stub, (const void *)(stubptr & ~1), sizeof(stub));
  if (ret < 0) {
    LOG("Failed to read stub %p, %x", stubptr, ret);
    return ret;
  }
  // FIXME: find a better way to do this
  if (stub[0] == 0xE24FC008 && stub[1] == 0xE12FFF1E) {
    LOG("stub for %p has not been resolved yet!", import_func_nid);
    return TAI_ERROR_STUB_NOT_RESOLVED;
  }
  return taiHookFunctionAbs(pid, p_hook, (void *)stubptr, hook_func);
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
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to hook
 *             - TAI_ERROR_INVALID_KERNEL_ADDR if `pid` is kernel and address is in shared memory region
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
 *             - TAI_ERROR_INVALID_MODULE if `module` is `TAI_MAIN_MODULE`
 *               and `pid` is kernel
 */
int taiGetModuleInfoForKernel(SceUID pid, const char *module, tai_module_info_t *info) {
  return module_get_by_name_nid(pid, module, TAI_IGNORE_MODULE_NID, info);
}

/**
 * @brief      Release a hook
 *
 * @param[in]  tai_uid  The tai patch reference to free
 * @param[in]  hook     The hook to free
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to restore the function
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
 * @brief      Parses the taiHEN config and loads all plugins for a titleid to a
 *             process
 *
 *             `flags` are ignored!
 *
 * @param[in]  pid      The pid to load to
 * @param[in]  titleid  The title to read from the config
 * @param[in]  flags    Ignored.
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_SYSTEM if the config file is invalid
 */
int taiLoadPluginsForTitleForKernel(SceUID pid, const char *titleid, int flags) {
  return plugin_load_all(pid, titleid);
}

/**
 * @brief      Reloads config.txt from the default path and optionally loads
 *             kernel plugins.
 *
 *             If `schedule` is set, then if called from a plugin `module_start`
 *             handler, it will schedule a config reload (and optionally load
 *             kernel plugins) after the current config parsing is completed. If
 *             `load_kernel` is set, then load kernel plugins defined in
 *             `*KERNEL` from the config file as well after config is reloaded
 *             successfully.
 *
 * @param[in]  schedule     If blocking, schedule reload until after load is
 *                          complete.
 * @param[in]  load_kernel  Load all kernel plugins defined in config.
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_BLOCKING if attempted to call from plugin start and
 *               `schedule` _is not set_.
 */
int taiReloadConfigForKernel(int schedule, int load_kernel) {
  int ret;

  ret = plugin_load_config();
  if (ret == TAI_ERROR_BLOCKING && schedule) {
    plugin_delayed_load_config(load_kernel);
    ret = TAI_SUCCESS;
  }
  return ret;
}

/**
 * @brief      Module entry point
 *
 *             This module should be loaded by a kernel exploit. taiHEN expects
 *             the kernel environment to be clean, which means that no outside
 *             hooks and patches which may interfere with taiHEN.
 *
 *             If the user hold the L button while starting taiHEN, kernel
 *             plugins will be skipped.
 *
 * @param[in]  argc  Size of arguments (unused)
 * @param[in]  args  The arguments (unused)
 *
 * @return     Success always
 */
int module_start(SceSize argc, const void *args) {
  SceCtrlData ctrl;
  int ret;
  LOG("starting taihen...");
  ret = proc_map_init();
  if (ret < 0) {
    LOG("proc map init failed: %x", ret);
    return SCE_KERNEL_START_FAILED;
  }
  ret = patches_init();
  if (ret < 0) {
    LOG("patches init failed: %x", ret);
    return SCE_KERNEL_START_FAILED;
  }
  ret = plugin_init();
  if (ret < 0) {
    LOG("plugin init failed: %x", ret);
    return SCE_KERNEL_START_FAILED;
  }
  ret = hen_add_patches();
  if (ret < 0) {
    LOG("HEN patches failed: %x", ret);
    return SCE_KERNEL_START_FAILED;
  }
  ksceCtrlPeekBufferPositive(0, &ctrl, 1);
  LOG("buttons held: 0x%08X", ctrl.buttons);
  if (!(ctrl.buttons & (SCE_CTRL_LTRIGGER | SCE_CTRL_L1))) {
    ret = plugin_load_config();
    if (ret < 0) {
      LOG("HEN config load failed: %x", ret);
      return SCE_KERNEL_START_FAILED;
    }
    plugin_load_all(KERNEL_PID, "KERNEL");
  } else {
    LOG("skipping plugin loading");
  }
  return SCE_KERNEL_START_SUCCESS;
}

/**
 * @brief      Alias to inhibit compiler warning
 * @private
 */
void _start() __attribute__ ((weak, alias ("module_start")));

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
  // TODO: release everything
  hen_remove_patches();
  plugin_deinit();
  patches_deinit();
  proc_map_deinit();
  return SCE_KERNEL_STOP_SUCCESS;
}

/**
 * @brief      Module Exit handler (unused)
 *
 *             This function is currently unused on retail units.
 */
void module_exit(void) {

}
