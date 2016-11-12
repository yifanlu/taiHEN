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
#define MAX_ARGS_SIZE 256

/**
 * @brief      Add a hook to a module function export for the calling process
 *
 * @see        taiHookFunctionExportForKernel
 *
 * @param[out] p_hook  A reference that can be used by the hook function
 * @param[in]  args    Call arguments
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to
 *               hook
 *             - TAI_ERROR_NOT_IMPLEMENTED if address is in shared memory region
 *             - TAI_ERROR_USER_MEMORY if pointers are incorrect
 */
SceUID taiHookFunctionExportForUser(tai_hook_ref_t *p_hook, tai_hook_args_t *args) {
  tai_hook_args_t kargs;
  uint32_t func_nid;
  const void *hook_func;
  uint32_t state;
  char k_module[MAX_NAME_LEN];
  tai_hook_ref_t k_ref;
  SceUID kid, ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  kargs.size = 0;
  sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = sceKernelGetProcessId();
    if (sceKernelStrncpyUserToKernel(k_module, (uintptr_t)kargs.module, MAX_NAME_LEN) < MAX_NAME_LEN) {
      kid = taiHookFunctionExportForKernel(pid, &k_ref, k_module, kargs.library_nid, kargs.func_nid, kargs.hook_func);
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
  } else {
    LOG("invalid args size: %x", kargs.size);
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
 * @param[out] p_hook  A reference that can be used by the hook function
 * @param[in]  args    Call arguments
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to
 *               hook
 *             - TAI_ERROR_NOT_IMPLEMENTED if address is in shared memory region
 *             - TAI_ERROR_USER_MEMORY if pointers are incorrect
 *             - TAI_ERROR_STUB_NOT_RESOLVED if the import has not been resolved
 *               yet. You should hook `sceKernelLoadStartModule`,
 *               `sceSysmoduleLoadModule` or whatever the application uses to
 *               start the imported module and add this hook after the module is
 *               loaded. Be sure to also hook module unloading to remove the
 *               hook BEFORE the imported module is unloaded!
 */
SceUID taiHookFunctionImportForUser(tai_hook_ref_t *p_hook, tai_hook_args_t *args) {
  tai_hook_args_t kargs;
  uint32_t state;
  char k_module[MAX_NAME_LEN];
  tai_hook_ref_t k_ref;
  SceUID kid, ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = sceKernelGetProcessId();
    if (sceKernelStrncpyUserToKernel(k_module, (uintptr_t)kargs.module, MAX_NAME_LEN) < MAX_NAME_LEN) {
      kid = taiHookFunctionImportForKernel(pid, &k_ref, k_module, kargs.library_nid, kargs.func_nid, kargs.hook_func);
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
  } else {
    LOG("invalid args size: %x", kargs.size);
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
 * @param[out] p_hook  A reference that can be used by the hook function
 * @param[in]  args    Call arguments
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 *             - TAI_ERROR_HOOK_ERROR if an internal error occurred trying to
 *               hook
 *             - TAI_ERROR_NOT_IMPLEMENTED if address is in shared memory region
 *             - TAI_ERROR_USER_MEMORY if pointers are incorrect
 */
SceUID taiHookFunctionOffsetForUser(tai_hook_ref_t *p_hook, tai_offset_args_t *args) {
  tai_offset_args_t kargs;
  uint32_t state;
  tai_hook_ref_t k_ref;
  SceUID ret;
  SceUID pid;
  SceUID kid;

  ENTER_SYSCALL(state);
  kargs.size = 0;
  sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = sceKernelGetProcessId();
    kid = sceKernelKernelUidForUserUid(pid, kargs.modid);
    if (kid >= 0) {
      ret = taiHookFunctionOffsetForKernel(pid, &k_ref, kid, kargs.segidx, kargs.offset, kargs.thumb, kargs.source);
      if (ret >= 0) {
        sceKernelMemcpyKernelToUser((uintptr_t)p_hook, &k_ref, sizeof(*p_hook));
        ret = sceKernelCreateUserUid(pid, ret);
        LOG("user uid: %x", ret);
      }
    } else {
      LOG("Error getting kernel uid for %x: %x", kargs.modid, kid);
      ret = kid;
    }
  } else {
    LOG("invalid args size: %x", kargs.size);
    ret = TAI_ERROR_USER_MEMORY;
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
 * @param[in]  args   Call arguments
 *
 * @return     A tai patch reference on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if the address is already patched
 */
SceUID taiInjectDataForUser(tai_offset_args_t *args) {
  tai_offset_args_t kargs;
  uint32_t state;
  tai_hook_ref_t k_ref;
  SceUID ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  kargs.size = 0;
  sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = sceKernelGetProcessId();
    ret = sceKernelKernelUidForUserUid(pid, kargs.modid);
    if (ret >= 0) {
      kargs.modid = ret;
      ret = taiInjectDataForKernel(pid, kargs.modid, kargs.segidx, kargs.offset, kargs.source, kargs.source_size);
      if (ret >= 0) {
        ret = sceKernelCreateUserUid(pid, ret);
        LOG("user uid: %x", ret);
      }
    } else {
      LOG("Error getting kernel uid for %x: %x", kargs.modid, ret);
    }
  } else {
    LOG("invalid args size: %x", kargs.size);
    ret = TAI_ERROR_USER_MEMORY;
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
  SceUID pid;
  int ret;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    if (opt == NULL) {
      if (sceKernelStrncpyUserToKernel(k_path, (uintptr_t)path, MAX_NAME_LEN) < MAX_NAME_LEN) {
        ret = sceKernelLoadModuleForDriver(k_path, flags, NULL);
        LOG("loaded %s: %x", k_path, ret);
        if (ret >= 0) {
          ret = sceKernelCreateUserUid(pid, ret);
          LOG("user uid: %x", ret);
        }
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
 * @param[in]  args   The arguments
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_start`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large or `opt` is not
 *               NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiStartKernelModuleForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res) {
  tai_module_args_t kargs;
  char buf[MAX_ARGS_SIZE];
  uint32_t state;
  int ret;
  int k_res;
  SceUID pid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    kargs.size = 0;
    sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        ret = sceKernelKernelUidForUserUid(pid, modid);
        if (ret >= 0) {
          modid = ret;
          ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = sceKernelStartModuleForDriver(modid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              sceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
          }
        } else {
          LOG("Error getting kernel uid for %x: %x", modid, ret);
        }
      } else {
        LOG("invalid args size: %x", kargs.size);
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
 * @brief      Loads and starts a kernel module
 *
 * @param[in]  path  The path of the skprx
 * @param[in]  args  The arguments
 *
 * @return     A module reference on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
SceUID taiLoadStartKernelModuleForUser(const char *path, tai_module_args_t *args) {
  tai_module_args_t kargs;
  char buf[MAX_ARGS_SIZE];
  char k_path[MAX_NAME_LEN];
  uint32_t state;
  SceUID modid;
  int ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    kargs.size = 0;
    sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE) {
        ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
        if (ret >= 0) {
          ret = sceKernelLoadStartModuleForDriver(k_path, kargs.args, buf, kargs.flags, NULL, NULL);
          LOG("loaded %s: %x", k_path, ret);
          if (ret >= 0) {
            ret = sceKernelCreateUserUid(pid, ret);
            LOG("user uid: %x", ret);
          }
        }
      } else {
        ret = TAI_ERROR_INVALID_ARGS;
      }
    } else {
      LOG("invalid args size: %x", kargs.size);
      ret = TAI_ERROR_USER_MEMORY;
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Loads and starts a user module for another process
 *
 * @param[in]  path  The path of the skprx
 * @param[in]  args  The arguments
 *
 * @return     A module reference on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
SceUID taiLoadStartModuleForPidForUser(const char *path, tai_module_args_t *args) {
  tai_module_args_t kargs;
  char buf[MAX_ARGS_SIZE];
  char k_path[MAX_NAME_LEN];
  uint32_t state;
  SceUID modid;
  int ret;


  ENTER_SYSCALL(state);
  if (sceSblACMgrIsShell(0)) {
    kargs.size = 0;
    sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE) {
        ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
        if (ret >= 0) {
          ret = sceKernelLoadStartModuleForPid(kargs.pid, k_path, kargs.args, buf, kargs.flags, NULL, NULL);
          LOG("loaded %s: %x", k_path, ret);
          if (ret >= 0) {
            ret = sceKernelCreateUserUid(kargs.pid, ret);
            LOG("user uid: %x", ret);
          }
        }
      } else {
        ret = TAI_ERROR_INVALID_ARGS;
      }
    } else {
      LOG("invalid args size: %x", kargs.size);
      ret = TAI_ERROR_USER_MEMORY;
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Stops a kernel module
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The arguments
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large or `opt` is not NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiStopKernelModuleForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res) {
  tai_module_args_t kargs;
  char buf[MAX_ARGS_SIZE];
  uint32_t state;
  int ret;
  int k_res;
  SceUID pid;
  SceUID kid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    kargs.size = 0;
    sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = sceKernelKernelUidForUserUid(pid, modid);
        if (kid >= 0) {
          ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = sceKernelStopModuleForDriver(kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              sceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              sceKernelDeleteUserUid(pid, modid);
            }
          }
        } else {
          LOG("Error getting kernel uid for %x: %x", modid, kid);
          ret = kid;
        }
      } else {
        ret = TAI_ERROR_INVALID_ARGS;
      }
    } else {
      LOG("invalid args size: %x", kargs.size);
      ret = TAI_ERROR_USER_MEMORY;
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
 * @param      opt    Set to `NULL`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiUnloadKernelModule(SceUID modid, int flags, void *opt) {
  uint32_t state;
  SceUID pid;
  SceUID kid;
  int ret;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    if (opt == NULL) {
      kid = sceKernelKernelUidForUserUid(pid, modid);
      if (kid >= 0) {
        ret = sceKernelUnloadModuleForDriver(kid, flags, NULL);
        if (ret >= 0) {
          sceKernelDeleteUserUid(pid, modid);
        }
      } else {
        LOG("Error getting kernel uid for %x: %x", modid, kid);
        ret = kid;
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
 * @brief      Stops and unloads a kernel module
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The arguments
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large or `opt` is not NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiStopUnloadKernelModuleForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res) {
  tai_module_args_t kargs;
  char buf[MAX_ARGS_SIZE];
  uint32_t state;
  int ret;
  int k_res;
  SceUID pid;
  SceUID kid;

  ENTER_SYSCALL(state);
  pid = sceKernelGetProcessId();
  if (sceSblACMgrIsShell(0)) {
    kargs.size = 0;
    sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = sceKernelKernelUidForUserUid(pid, modid);
        if (kid >= 0) {
          ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = sceKernelStopUnloadModuleForDriver(kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              sceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              sceKernelDeleteUserUid(pid, modid);
            }
          }
        } else {
          LOG("Error getting kernel uid for %x: %x", modid, kid);
          ret = kid;
        }
      } else {
        ret = TAI_ERROR_INVALID_ARGS;
      }
    } else {
      LOG("invalid args size: %x", kargs.size);
      ret = TAI_ERROR_USER_MEMORY;
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Stops a user module for another process
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The arguments
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large or `opt` is not NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiStopModuleForPidForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res) {
  tai_module_args_t kargs;
  char buf[MAX_ARGS_SIZE];
  uint32_t state;
  int ret;
  int k_res;
  SceUID kid;

  ENTER_SYSCALL(state);
  if (sceSblACMgrIsShell(0)) {
    kargs.size = 0;
    sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = sceKernelKernelUidForUserUid(kargs.pid, modid);
        if (kid >= 0) {
          ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = sceKernelStopModuleForPid(kargs.pid, kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              sceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              sceKernelDeleteUserUid(kargs.pid, modid);
            }
          }
        } else {
          LOG("Error getting kernel uid for %x: %x", modid, kid);
          ret = kid;
        }
      } else {
        ret = TAI_ERROR_INVALID_ARGS;
      }
    } else {
      LOG("invalid args size: %x", kargs.size);
      ret = TAI_ERROR_USER_MEMORY;
    }
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}

/**
 * @brief      Unloads a user module for a process directly
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  flags  The flags
 * @param      opt    Set to `NULL`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiUnloadModuleForPid(SceUID pid, SceUID modid, int flags, void *opt) {
  uint32_t state;
  SceUID kid;
  int ret;

  ENTER_SYSCALL(state);
  if (sceSblACMgrIsShell(0)) {
    if (opt == NULL) {
      kid = sceKernelKernelUidForUserUid(pid, modid);
      if (kid >= 0) {
        ret = sceKernelUnloadModuleForPid(pid, kid, flags, NULL);
        if (ret >= 0) {
          sceKernelDeleteUserUid(pid, modid);
        }
      } else {
        LOG("Error getting kernel uid for %x: %x", modid, kid);
        ret = kid;
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
 * @brief      Stops and unloads a user module for a process
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The arguments
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_ARGS if `args` is too large or `opt` is not NULL
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 */
int taiStopUnloadModuleForPidForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res) {
  tai_module_args_t kargs;
  char buf[MAX_ARGS_SIZE];
  uint32_t state;
  int ret;
  int k_res;
  SceUID kid;

  ENTER_SYSCALL(state);
  if (sceSblACMgrIsShell(0)) {
    kargs.size = 0;
    sceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = sceKernelKernelUidForUserUid(kargs.pid, modid);
        if (kid >= 0) {
          ret = sceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = sceKernelStopUnloadModuleForPid(kargs.pid, kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              sceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              sceKernelDeleteUserUid(kargs.pid, modid);
            }
          }
        } else {
          LOG("Error getting kernel uid for %x: %x", modid, kid);
          ret = kid;
        }
      } else {
        ret = TAI_ERROR_INVALID_ARGS;
      }
    } else {
      LOG("invalid args size: %x", kargs.size);
      ret = TAI_ERROR_USER_MEMORY;
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
