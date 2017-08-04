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
#include "plugin.h"
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
 *             - TAI_ERROR_INVALID_MODULE if `TAI_MAIN_MODULE` is specified and
 *               there are multiple main modules
 */
SceUID taiHookFunctionExportForUser(tai_hook_ref_t *p_hook, tai_hook_args_t *args) {
  tai_hook_args_t kargs;
  uint32_t func_nid;
  const void *hook_func;
  uint32_t state;
  char k_module[MAX_NAME_LEN];
  int main_mod;
  tai_hook_ref_t k_ref;
  SceUID kid, ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  kargs.size = 0;
  ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = ksceKernelGetProcessId();
    main_mod = (kargs.module == TAI_MAIN_MODULE);
    if (main_mod || ksceKernelStrncpyUserToKernel(k_module, (uintptr_t)kargs.module, MAX_NAME_LEN) < MAX_NAME_LEN) {
      kid = taiHookFunctionExportForKernel(pid, &k_ref, main_mod ? kargs.module : k_module, kargs.library_nid, kargs.func_nid, kargs.hook_func);
      if (kid >= 0) {
        ksceKernelMemcpyKernelToUser((uintptr_t)p_hook, &k_ref, sizeof(*p_hook));
        ret = ksceKernelCreateUserUid(pid, kid);
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
 *             - TAI_ERROR_NOT_IMPLEMENTED if address is in shared memory
 *               region. You should hook an import from another module instead.
 *             - TAI_ERROR_USER_MEMORY if pointers are incorrect
 *             - TAI_ERROR_STUB_NOT_RESOLVED if the import has not been resolved
 *               yet. You should hook `sceKernelLoadStartModule`,
 *               `sceSysmoduleLoadModule` or whatever the application uses to
 *               start the imported module and add this hook after the module is
 *               loaded. Be sure to also hook module unloading to remove the
 *               hook BEFORE the imported module is unloaded!
 *             - TAI_ERROR_INVALID_MODULE if `TAI_MAIN_MODULE` is specified and
 *               there are multiple main modules
 */
SceUID taiHookFunctionImportForUser(tai_hook_ref_t *p_hook, tai_hook_args_t *args) {
  tai_hook_args_t kargs;
  uint32_t state;
  char k_module[MAX_NAME_LEN];
  int main_mod;
  tai_hook_ref_t k_ref;
  SceUID kid, ret;
  SceUID pid;

  ENTER_SYSCALL(state);
  ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = ksceKernelGetProcessId();
    main_mod = (kargs.module == TAI_MAIN_MODULE);
    if (main_mod || ksceKernelStrncpyUserToKernel(k_module, (uintptr_t)kargs.module, MAX_NAME_LEN) < MAX_NAME_LEN) {
      kid = taiHookFunctionImportForKernel(pid, &k_ref, main_mod ? kargs.module : k_module, kargs.library_nid, kargs.func_nid, kargs.hook_func);
      if (kid >= 0) {
        ksceKernelMemcpyKernelToUser((uintptr_t)p_hook, &k_ref, sizeof(*p_hook));
        ret = ksceKernelCreateUserUid(pid, kid);
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
  ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = ksceKernelGetProcessId();
    kid = ksceKernelKernelUidForUserUid(pid, kargs.modid);
    if (kid >= 0) {
      ret = taiHookFunctionOffsetForKernel(pid, &k_ref, kid, kargs.segidx, kargs.offset, kargs.thumb, kargs.source);
      if (ret >= 0) {
        ksceKernelMemcpyKernelToUser((uintptr_t)p_hook, &k_ref, sizeof(*p_hook));
        ret = ksceKernelCreateUserUid(pid, ret);
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
 *             You can use the macro `TAI_MAIN_MODULE` for `module` to specify
 *             the main module. This is usually the module that is loaded first
 *             and is usually the eboot.bin. This will only work if there is
 *             only one module loaded in the main memory space. Not all
 *             processes have this property! Make sure you check the return
 *             value.
 *
 * @see        taiGetModuleInfoForKernel
 *
 * @param[in]  module  The name of the module or `TAI_MAIN_MODULE`.
 * @param[out] info    The information to fill
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_USER_MEMORY if `info->size` is too small or large or
 *               `module` is invalid
 *             - TAI_ERROR_INVALID_MODULE if `TAI_MAIN_MODULE` is specified and
 *               there are multiple main modules
 */
int taiGetModuleInfo(const char *module, tai_module_info_t *info) {
  int main_mod;
  char k_module[MAX_NAME_LEN];
  uint32_t state;
  SceUID pid;
  tai_module_info_t k_info;
  int ret;

  ENTER_SYSCALL(state);
  pid = ksceKernelGetProcessId();
  main_mod = (module == TAI_MAIN_MODULE);
  if (main_mod || ksceKernelStrncpyUserToKernel(k_module, (uintptr_t)module, MAX_NAME_LEN) < MAX_NAME_LEN) {
    ksceKernelMemcpyUserToKernel(&k_info, (uintptr_t)info, sizeof(size_t));
    if (k_info.size == sizeof(k_info)) {
      ret = taiGetModuleInfoForKernel(pid, main_mod ? module : k_module, &k_info);
      ksceKernelMemcpyKernelToUser((uintptr_t)info, &k_info, k_info.size);
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
  pid = ksceKernelGetProcessId();
  kid = ksceKernelKernelUidForUserUid(pid, tai_uid);
  if (kid >= 0) {
    ret = taiHookReleaseForKernel(kid, hook);
    ksceKernelDeleteUserUid(pid, tai_uid);
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
  pid = ksceKernelGetProcessId();
  ret = taiInjectAbsForKernel(pid, dest, src, size);
  if (ret >= 0) {
    ret = ksceKernelCreateUserUid(pid, ret);
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
  ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
  if (kargs.size == sizeof(kargs)) {
    pid = ksceKernelGetProcessId();
    ret = ksceKernelKernelUidForUserUid(pid, kargs.modid);
    if (ret >= 0) {
      kargs.modid = ret;
      ret = taiInjectDataForKernel(pid, kargs.modid, kargs.segidx, kargs.offset, kargs.source, kargs.source_size);
      if (ret >= 0) {
        ret = ksceKernelCreateUserUid(pid, ret);
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
  pid = ksceKernelGetProcessId();
  kid = ksceKernelKernelUidForUserUid(pid, tai_uid);
  if (kid >= 0) {
    ret = taiInjectReleaseForKernel(kid);
    ksceKernelDeleteUserUid(pid, tai_uid);
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
  pid = ksceKernelGetProcessId();
  if (ksceSblACMgrIsShell(0)) {
    if (opt == NULL) {
      if (ksceKernelStrncpyUserToKernel(k_path, (uintptr_t)path, MAX_NAME_LEN) < MAX_NAME_LEN) {
        ret = ksceKernelLoadModule(k_path, flags, NULL);
        LOG("loaded %s: %x", k_path, ret);
        if (ret >= 0) {
          ret = ksceKernelCreateUserUid(pid, ret);
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
  pid = ksceKernelGetProcessId();
  if (ksceSblACMgrIsShell(0)) {
    kargs.size = 0;
    ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        ret = ksceKernelKernelUidForUserUid(pid, modid);
        if (ret >= 0) {
          modid = ret;
          ret = ksceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = ksceKernelStartModule(modid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              ksceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
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
  pid = ksceKernelGetProcessId();
  if (ksceSblACMgrIsShell(0)) {
    kargs.size = 0;
    ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE) {
        ret = ksceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
        if (ret >= 0) {
          if (ksceKernelStrncpyUserToKernel(k_path, (uintptr_t)path, MAX_NAME_LEN) < MAX_NAME_LEN) {
            ret = ksceKernelLoadStartModule(k_path, kargs.args, buf, kargs.flags, NULL, NULL);
            LOG("loaded %s: %x", k_path, ret);
            if (ret >= 0) {
              ret = ksceKernelCreateUserUid(pid, ret);
              LOG("user uid: %x", ret);
            }
          } else {
            ret = TAI_ERROR_USER_MEMORY;
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
  if (ksceSblACMgrIsShell(0)) {
    kargs.size = 0;
    ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE) {
        ret = ksceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
        if (ret >= 0) {
          if (ksceKernelStrncpyUserToKernel(k_path, (uintptr_t)path, MAX_NAME_LEN) < MAX_NAME_LEN) {
            ret = ksceKernelLoadStartModuleForPid(kargs.pid, k_path, kargs.args, buf, kargs.flags, NULL, NULL);
            LOG("loaded %s: %x", k_path, ret);
            if (ret >= 0) {
              ret = ksceKernelCreateUserUid(kargs.pid, ret);
              LOG("user uid: %x", ret);
            }
          } else {
            ret = TAI_ERROR_USER_MEMORY;
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
  pid = ksceKernelGetProcessId();
  if (ksceSblACMgrIsShell(0)) {
    kargs.size = 0;
    ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = ksceKernelKernelUidForUserUid(pid, modid);
        if (kid >= 0) {
          ret = ksceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = ksceKernelStopModule(kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              ksceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              ksceKernelDeleteUserUid(pid, modid);
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
  pid = ksceKernelGetProcessId();
  if (ksceSblACMgrIsShell(0)) {
    if (opt == NULL) {
      kid = ksceKernelKernelUidForUserUid(pid, modid);
      if (kid >= 0) {
        ret = ksceKernelUnloadModule(kid, flags, NULL);
        if (ret >= 0) {
          ksceKernelDeleteUserUid(pid, modid);
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
  pid = ksceKernelGetProcessId();
  if (ksceSblACMgrIsShell(0)) {
    kargs.size = 0;
    ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = ksceKernelKernelUidForUserUid(pid, modid);
        if (kid >= 0) {
          ret = ksceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = ksceKernelStopUnloadModule(kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              ksceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              ksceKernelDeleteUserUid(pid, modid);
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
  if (ksceSblACMgrIsShell(0)) {
    kargs.size = 0;
    ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = ksceKernelKernelUidForUserUid(kargs.pid, modid);
        if (kid >= 0) {
          ret = ksceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = ksceKernelStopModuleForPid(kargs.pid, kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              ksceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              ksceKernelDeleteUserUid(kargs.pid, modid);
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
  if (ksceSblACMgrIsShell(0)) {
    if (opt == NULL) {
      kid = ksceKernelKernelUidForUserUid(pid, modid);
      if (kid >= 0) {
        ret = ksceKernelUnloadModuleForPid(pid, kid, flags, NULL);
        if (ret >= 0) {
          ksceKernelDeleteUserUid(pid, modid);
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
  if (ksceSblACMgrIsShell(0)) {
    kargs.size = 0;
    ksceKernelMemcpyUserToKernel(&kargs, (uintptr_t)args, sizeof(kargs));
    if (kargs.size == sizeof(kargs)) {
      if (kargs.args <= MAX_ARGS_SIZE && opt == NULL) {
        kid = ksceKernelKernelUidForUserUid(kargs.pid, modid);
        if (kid >= 0) {
          ret = ksceKernelMemcpyUserToKernel(buf, (uintptr_t)kargs.argp, kargs.args);
          if (ret >= 0) {
            k_res = 0;
            ret = ksceKernelStopUnloadModuleForPid(kargs.pid, kid, kargs.args, buf, kargs.flags, NULL, &k_res);
            if (res) {
              ksceKernelMemcpyKernelToUser((uintptr_t)res, &k_res, sizeof(*res));
            }
            if (ret >= 0) {
              ksceKernelDeleteUserUid(kargs.pid, modid);
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
 * @brief      Gets an exported function address for a module of the calling process
 *
 * @param[in]  modname  The name of module to lookup
 * @param[in]  libnid   NID of the exporting library. Can be `TAI_ANY_LIBRARY`.
 * @param[in]  funcnid  NID of the exported function
 * @param[out] func     Output address of the function
 *
 * @return     Zero on success, < 0 on error
 */
int taiGetModuleExportFunc(const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func) {
  char k_module[MAX_NAME_LEN];
  uintptr_t k_func;
  uint32_t state;
  SceUID pid;
  int ret;

  ENTER_SYSCALL(state);
  pid = ksceKernelGetProcessId();
  if (ksceKernelStrncpyUserToKernel(k_module, (uintptr_t)modname, MAX_NAME_LEN) < MAX_NAME_LEN) {
    ret = module_get_export_func(pid, k_module, libnid, funcnid, &k_func);
    if (ret == 0) {
      ksceKernelMemcpyKernelToUser((uintptr_t)func, &k_func, sizeof(k_func));
    }
  } else {
    ret = TAI_ERROR_USER_MEMORY;
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
  if (ksceSblACMgrIsShell(0)) {
    ret = 0;
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  if (ret == 0) {
    return ksceKernelMemcpyUserToKernel(kernel_dst, (uintptr_t)user_src, len);
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
  if (ksceSblACMgrIsShell(0)) {
    ret = 0;
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  if (ret == 0) {
    return ksceKernelMemcpyKernelToUser((uintptr_t)user_dst, kernel_src, len);
  } else {
    return ret;
  }
}

/**
 * @brief      Reloads config.txt from the default path
 *
 *             Note this cannot be called from a plugin start handler!
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_NOT_ALLOWED if caller does not have permission
 *             - TAI_ERROR_BLOCKING if attempted to call recursively
 */
int taiReloadConfig(void) {
  uint32_t state;
  int ret;

  ENTER_SYSCALL(state);
  if (ksceSblACMgrIsShell(0)) {
    ret = taiReloadConfigForKernel(0, 0);
  } else {
    ret = TAI_ERROR_NOT_ALLOWED;
  }
  EXIT_SYSCALL(state);
  return ret;
}
