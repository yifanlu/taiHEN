/* taihen-user.c -- user exports for taiHEN
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/sblacmgr.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2/kernel/error.h>
#include "error.h"
#include "module.h"
#include "patches.h"
#include "taihen_internal.h"

/** Limit for strings passed to kernel */
#define MAX_NAME_LEN 256

/** Limit for passing args to start module */
#define MAX_ARGS_SIZE 0x1000

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
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to hook
 *             - TAI_ERROR_NOT_IMPLEMENTED if address is in shared memory region
 *             - TAI_ERROR_USER_MEMORY if pointers are incorrect
 */
SceUID taiHookFunctionExport(tai_hook_ref_t *p_hook, const char *module, uint32_t library_nid, uint32_t func_nid, const void *hook_func) {
  uint32_t state;
  char k_module[MAX_NAME_LEN];
  tai_hook_ref_t k_ref;
  SceUID kid, ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceKernelStrncpyUserToKernel(k_module, (uintptr_t)module, MAX_NAME_LEN) < MAX_NAME_LEN) {
    kid = taiHookFunctionExportForKernel(pid, &k_ref, k_module, library_nid, func_nid, hook_func);
    if (kid >= 0) {
      sceKernelMemcpyKernelToUser((uintptr_t)p_hook, &k_ref, sizeof(*p_hook));
      ret = sceKernelCreateUserUid(pid, kid);
      LOG("kernel uid: %x, user uid: %x", kid, ret);
    } else {
      ret = kid;
    }
  } else {
    ret = TAI_ERROR_USER_MEMORY;
  }
  EXIT_SYSCALL(state);
  return ret;
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
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to hook
 *             - TAI_ERROR_NOT_IMPLEMENTED if address is in shared memory region
 *             - TAI_ERROR_USER_MEMORY if pointers are incorrect
 */
SceUID taiHookFunctionImport(tai_hook_ref_t *p_hook, const char *module, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func) {
  uint32_t state;
  char k_module[MAX_NAME_LEN];
  tai_hook_ref_t k_ref;
  SceUID kid, ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceKernelStrncpyUserToKernel(k_module, (uintptr_t)module, MAX_NAME_LEN) < MAX_NAME_LEN) {
    kid = taiHookFunctionImportForKernel(pid, &k_ref, k_module, import_library_nid, import_func_nid, hook_func);
    if (kid >= 0) {
      sceKernelMemcpyKernelToUser((uintptr_t)p_hook, &k_ref, sizeof(*p_hook));
      ret = sceKernelCreateUserUid(pid, kid);
      LOG("kernel uid: %x, user uid: %x", kid, ret);
    } else {
      ret = kid;
    }
  } else {
    ret = TAI_ERROR_USER_MEMORY;
  }
  EXIT_SYSCALL(state);
  return ret;
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
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to hook
 *             - TAI_ERROR_NOT_IMPLEMENTED if address is in shared memory region
 *             - TAI_ERROR_USER_MEMORY if pointers are incorrect
 */
SceUID taiHookFunctionOffset(tai_hook_ref_t *p_hook, SceUID modid, int segidx, uint32_t offset, int thumb, const void *hook_func) {
  uint32_t state;
  tai_hook_ref_t k_ref;
  SceUID ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  ret = sceKernelKernelUidForUserUid(pid, modid);
  if (ret >= 0) {
    modid = ret;
    ret = taiHookFunctionOffsetForKernel(pid, &k_ref, modid, segidx, offset, thumb, hook_func);
    if (ret >= 0) {
      sceKernelMemcpyKernelToUser((uintptr_t)p_hook, &k_ref, sizeof(*p_hook));
      ret = sceKernelCreateUserUid(pid, ret);
      LOG("user uid: %x", ret);
    }
  } else {
    LOG("Error getting kernel uid for %x: %x", modid, ret);
  }
  EXIT_SYSCALL(state);
  return ret;
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
 *             - TAI_ERROR_USER_MEMORY if `info->size` is too small or large or
 *               `module` is invalid
 */
int taiGetModuleInfo(const char *module, tai_module_info_t *info) {
  char k_module[MAX_NAME_LEN];
  uint32_t state;
  SceUID pid;
  tai_module_info_t k_info;
  int ret;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceKernelStrncpyUserToKernel(k_module, (uintptr_t)module, MAX_NAME_LEN) < MAX_NAME_LEN) {
    sceKernelMemcpyUserToKernel(&k_info, (uintptr_t)info, sizeof(size_t));
    if (k_info.size == sizeof(k_info)) {
      ret = taiGetModuleInfoForKernel(pid, k_module, &k_info);
      sceKernelMemcpyKernelToUser((uintptr_t)info, &k_info, k_info.size);
    } else {
      ret = TAI_ERROR_USER_MEMORY;
    }
  } else {
    ret = TAI_ERROR_USER_MEMORY;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Release a hook for the calling process
 *
 * @see        taiHookReleaseForKernel
 *
 * @param[in]  tai_uid  The tai patch reference to free
 * @param[in]  hook     The hook to free
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to restore the function
 */
int taiHookRelease(SceUID tai_uid, tai_hook_ref_t hook) {
  uint32_t state;
  SceUID pid, kid;
  int ret;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  kid = sceKernelKernelUidForUserUid(pid, tai_uid);
  if (kid >= 0) {
    ret = taiHookReleaseForKernel(kid, hook);
    sceKernelDeleteUserUid(pid, tai_uid);
  } else {
    ret = kid;
  }
  EXIT_SYSCALL(state);
  return ret;
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
  uint32_t state;
  tai_hook_ref_t k_ref;
  SceUID ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  ret = taiInjectAbsForKernel(pid, dest, src, size);
  if (ret >= 0) {
    ret = sceKernelCreateUserUid(pid, ret);
    LOG("user uid: %x", ret);
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Inject data into the current process bypassing MMU flags given an
 *             offset
 *
 * @see        taiInjectDataForKernel
 *
 * @param[in]  modid   The module UID from `taiGetModuleInfo`
 * @param[in]  segidx  Index of the ELF segment containing the data to patch
 * @param[in]  offset  The offset from the start of the segment
 * @param[in]  data    Source data
 * @param[in]  size    The size of the injection in bytes
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiInjectData(SceUID modid, int segidx, uint32_t offset, const void *data, size_t size) {
  uint32_t state;
  tai_hook_ref_t k_ref;
  SceUID ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  ret = sceKernelKernelUidForUserUid(pid, modid);
  if (ret >= 0) {
    modid = ret;
    ret = taiInjectDataForKernel(pid, modid, segidx, offset, data, size);
    if (ret >= 0) {
      ret = sceKernelCreateUserUid(pid, ret);
      LOG("user uid: %x", ret);
    }
  } else {
    LOG("Error getting kernel uid for %x: %x", modid, ret);
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Release an injection for the calling process
 *
 * @see        taiInjectReleaseForKernel
 *
 * @param[in]  tai_uid  The tai patch reference to free
 *
 * @return     Zero on success, < 0 on error
 */
int taiInjectRelease(SceUID tai_uid) {
  uint32_t state;
  SceUID pid, kid;
  int ret;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  kid = sceKernelKernelUidForUserUid(pid, tai_uid);
  if (kid >= 0) {
    ret = taiInjectReleaseForKernel(kid);
    sceKernelDeleteUserUid(pid, tai_uid);
  } else {
    ret = kid;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Loads a kernel module
 *
 * @param[in]  path   The path to the skprx
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 *
 * @return     A module reference on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `opt` is not NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
SceUID taiLoadKernelModule(const char *path, int flags, void *opt) {
  uint32_t state;
  char k_path[MAX_NAME_LEN];
  SceKernelLMOption k_opt;
  SceUID pid;
  int ret;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    if (opt != NULL) {
      if (sceKernelStrncpyUserToKernel(k_path, (uintptr_t)path, MAX_NAME_LEN) < MAX_NAME_LEN) {
        k_opt.size = sizeof(k_opt);
        ret = sceKernelLoadModuleForDriver(k_path, flags, &k_opt);
        LOG("loaded %s: %x", k_path, ret);
        ret = sceKernelCreateUserUid(pid, ret);
        LOG("user uid: %x", ret);
      } else {
        ret = TAI_ERROR_USER_MEMORY;
      }
    } else {
      ret = TAI_ERROR_INVALID_ARGS;
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Starts a kernel module
 *
 * @param[in]  modid  The id from `taiLoadKernelModule`
 * @param[in]  args   The size of the arguments
 * @param      argp   The arguments
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_start`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large or `opt` is not NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiStartKernelModule(SceUID modid, int args, void *argp, int flags, void *opt, int *res) {
  char buf[MAX_ARGS_SIZE];
  uint32_t state;
  int ret;
  int k_res;
  SceUID pid;
  SceKernelLMOption k_opt;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    if (args <= MAX_ARGS_SIZE || opt != NULL) {
      ret = sceKernelKernelUidForUserUid(pid, modid);
      if (ret >= 0) {
        modid = ret;
        ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)argp, args);
        if (ret >= 0) {
          k_opt.size = sizeof(k_opt);
          k_res = 0;
          ret = sceKernelStartModuleForDriver(modid, args, buf, flags, &k_opt, &k_res);
          sceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
        }
      } else {
        LOG("Error getting kernel uid for %x: %x", modid, ret);
      }
    } else {
      ret = TAI_ERROR_INVALID_ARGS;
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Loads and starts a kernel module
 *
 * @param[in]  path   The path of the skprx
 * @param[in]  args   The size of the arguments
 * @param      argp   The arguments
 * @param[in]  flags  The flags
 *
 * @return     A module reference on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
SceUID taiLoadStartKernelModule(const char *path, int args, void *argp, int flags) {
  SceUID modid;
  int ret;

  modid = taiLoadKernelModule(path, flags, NULL);
  if (modid >= 0) {
    ret = taiStartKernelModule(modid, args, argp, flags, NULL, NULL);
    if (ret >= 0) {
      ret = modid;
    }
  } else {
    ret = modid;
  }
  return ret;
}

/**
 * @brief      Stops and unloads a kernel module
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The size of the arguments to `module_stop`
 * @param      argp   The arguments to `module_stop`
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large or `opt` is not NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiStopUnloadKernelModule(SceUID modid, int args, void *argp, int flags, void *opt, int *res) {
  char buf[MAX_ARGS_SIZE];
  uint32_t state;
  int ret;
  int k_res;
  SceUID pid;
  SceUID kid;
  SceKernelULMOption k_opt;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    if (args <= MAX_ARGS_SIZE || opt != NULL) {
      kid = sceKernelKernelUidForUserUid(pid, modid);
      if (kid >= 0) {
        ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)argp, args);
        if (ret >= 0) {
          k_opt.size = sizeof(k_opt);
          k_res = 0;
          ret = sceKernelStopUnloadModuleForDriver(kid, args, buf, flags, &k_opt, &k_res);
          sceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
          sceKernelDeleteUserUid(pid, modid);
        }
      } else {
        LOG("Error getting kernel uid for %x: %x", modid, ret);
      }
    } else {
      ret = TAI_ERROR_INVALID_ARGS;
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Unloads a kernel module directly
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  flags  The flags
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiUnloadKernelModule(SceUID modid, int flags) {
  uint32_t state;
  SceUID pid;
  SceUID kid;
  int ret;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    kid = sceKernelKernelUidForUserUid(pid, modid);
    if (kid >= 0) {
      ret = sceKernelUnloadModuleForDriver(kid, flags);
      sceKernelDeleteUserUid(pid, modid);
    } else {
      LOG("Error getting kernel uid for %x: %x", modid, ret);
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Copies data from user to kernel
 *
 * @param      kernel_dst  The kernel address
 * @param[in]  user_src    The user address
 * @param[in]  len         The length
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiMemcpyUserToKernel(void *kernel_dst, const void *user_src, size_t len) {
  uint32_t state;
  int ret;

  ENTER_SYSCALL(state);
  if (sceSblACMgrIsShell(0)) {
    ret = 0;
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  if (ret == 0) {
    return sceKernelMemcpyUserToKernel(kernel_dst, (uintptr_t)user_src, len);
  } else {
    return ret;
  }
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
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiMemcpyKernelToUser(void *user_dst, const void *kernel_src, size_t len) {
  uint32_t state;
  int ret;

  ENTER_SYSCALL(state);
  if (sceSblACMgrIsShell(0)) {
    ret = 0;
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  if (ret == 0) {
    return sceKernelMemcpyKernelToUser((uintptr_t)user_dst, kernel_src, len);
  } else {
    return ret;
  }
}
