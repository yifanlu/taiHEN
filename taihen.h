/**
 * @brief      CFW framework for Vita
 */
#ifndef TAI_HEADER
#define TAI_HEADER

#ifdef __cplusplus
extern "C" {
#endif

#include <psp2kern/types.h>
#include <stdint.h>

/**
 * @defgroup   taihen API Interface
 * @brief      Provides basic helper utilities for plugins that aid in user to
 *             kernel interaction.
 *
 * @details    taiHEN proves three types of exports. First is a patch system for
 *             modifying code and read-only data. Second is basic peek/poke for
 *             the kernel. Third is support for loading kernel modules.
 *
 *             A common question is: when should I use hooks, injections, and
 *             peek/poke? If you wish to patch writable data in the kernel and
 *             you know the address, then `taiMemcpyKernelToUser` works. If you
 *             don't know the address but you know the offset from its ELF
 *             segment then use an injection. If it is read-only data, then use
 *             an injection. Finally, if you wish to patch a _function_ to run
 *             your own code, you should use a hook.
 */
/** @{ */

/** PID for kernel process */
#define KERNEL_PID 0x10005

/** Fake library NID indicating that any library NID would match. */
#define TAI_ANY_LIBRARY 0xFFFFFFFF

/** Fake module NID indicating that any module NID would match. */
#define TAI_IGNORE_MODULE_NID 0xFFFFFFFF

/** Fake module name indicating the current process's main module. */
#define TAI_MAIN_MODULE ((void *)0)

/** Functions for calling the syscalls with arguments */
#define HELPER inline static __attribute__((unused))

/**
 * @brief      Extended module information
 *
 *             This supplements the output of `sceKernelGetModuleInfo`
 */
typedef struct _tai_module_info {
  size_t size;                ///< Structure size, set to sizeof(tai_module_info_t)
  SceUID modid;               ///< Module UID
  uint32_t module_nid;        ///< Module NID
  char name[27];              ///< Module name
  uintptr_t exports_start;    ///< Pointer to export table in process address space
  uintptr_t exports_end;      ///< Pointer to end of export table
  uintptr_t imports_start;    ///< Pointer to import table in process address space
  uintptr_t imports_end;      ///< Pointer to end of import table
} tai_module_info_t;

/**
 * @brief      Pass hook arguments to kernel
 */
typedef struct _tai_hook_args {
  size_t size;
  const char *module;
  uint32_t library_nid;
  uint32_t func_nid;
  const void *hook_func;
} tai_hook_args_t;

/**
 * @brief      Pass offset arguments to kernel
 */
typedef struct _tai_offset_args {
  size_t size;
  SceUID modid;
  int segidx;
  uint32_t offset;
  int thumb;
  const void *source;
  size_t source_size;
} tai_offset_args_t;

/**
 * @brief      Pass module arguments to kernel
 */
typedef struct _tai_module_args {
  size_t size;
  SceUID pid;
  size_t args;
  void *argp;
  int flags;
} tai_module_args_t;

/**
 * @defgroup   hook Hooks Interface
 * @brief      Patches functions.
 *
 *  A function hook allows a plugin to run code before and after a
 *  any function call. As an example, say we wish to hook
 *  `ksceIoOpen`
 *
 *  ```c
 *  static tai_hook_ref_t open_ref;
 *  taiHookFunctionExportForKernel(KERNEL_PID, &open_ref, "SceIofilemgr", TAI_ANY_LIBRARY, 0x75192972, open_hook);
 *  ```
 *
 *  If we wish to log the path of any kernel file opens, we can write
 *  this
 *
 *  ```c
 *  SceUID open_hook(const char *path, int flags, SceMode mode) {
 *    printf("opened: %s\n", path);
 *    return TAI_CONTINUE(SceUID, open_ref, path, flags, mode);
 *  }
 *  ```
 *
 *  Note that it is the user's responsibility to ensure that the
 *  function prototype matches. What if we want to log the return
 *  values too?
 *
 *  ```c
 *  SceUID open_hook(const char *path, int flags, SceMode mode) {
 *    SceUID ret = TAI_CONTINUE(SceUID, open_ref, path, flags, mode);
 *    printf("opened: %s, return: %x\n", path, ret);
 *    return ret;
 *  }
 *  ```
 *
 *  For a more complicated example, we can redirect a file open as
 *  follows
 *
 *  ```c
 *  SceUID open_hook(const char *path, int flags, SceMode mode) {
 *    SceUID ret;
 *    
 *    if (strcmp(path, "ux0:id.dat") == 0) {
 *      path = "ux0:id-redirect.dat";
 *      printf("redirecting path\n");
 *    }
 *    
 *    ret = TAI_CONTINUE(SceUID, open_ref, path, flags, mode);
 *    printf("opened: %s, return: %x\n", path, ret);
 *    return ret;
 *  }
 *  ```
 *
 *  Note that we use the `TAI_CONTINUE` macro in order to continue
 *  the chain. You should _always do this_ because it ensures all
 *  hooks get their share of the pie. Consider this bad example
 *
 *  ```c
 *  SceUID bad_open_hook(const char *path, int flags, SceMode mode) {
 *    if (strcmp(path, "ux0:dontwant.bin") == 0) {
 *      return SCE_KERNEL_ERROR_NOENT;
 *    } else {
 *      return TAI_CONTINUE(SceUID, open_ref, path, flags, mode);
 *    }
 *  }
 *  ```
 *
 *  This prevents any other hooks from running. This would break, for
 *  example, our logging hook above. Instead you should do
 *
 *  ```c
 *  SceUID good_open_hook(const char *path, int flags, SceMode mode) {
 *    SceUID ret;
 *    ret = TAI_CONTINUE(SceUID, open_ref, path, flags, mode);
 *    if (strcmp(path, "ux0:dontwant.bin") == 0) {
 *      return SCE_KERNEL_ERROR_NOENT;
 *    } else {
 *      return ret;
 *    }
 *  }
 *  ```
 *
 *  Another common use case is the ability to call the original
 *  function. The recommended way of doing this is to make the
 *  original function call
 *
 *  ```c
 *  SceUID recurse_open_hook(const char *path, int flags, SceMode mode) {
 *    const char *log = "ux0:lastopen.txt";
 *    SceUID ret;
 *    SceUID fd;
 *    ret = TAI_CONTINUE(SceUID, open_ref, path, flags, mode);
 *    if (path != log && strncmp(path, "ux0:", 4) == 0) {
 *      fd = ksceIoOpen(log, SCE_O_WRONLY, 0);
 *      sceIoWrite(fd, path, 256);
 *      sceIoClose(fd);
 *    }
 *    return ret;
 *  }
 *  ```
 *
 *  Note that calling the original `ksceIoOpen` will recurse
 *  back to `recurse_open_hook` so it is _very important_ to avoid an
 *  infinite recursion. In this case, we check that the parameter is
 *  not the same, but more complex checks may be needed for other 
 *  function.
 */
/** @{ */

/**
 * @brief      Hook information
 *
 *             This reference is created on new hooks and is up to the caller to
 *             keep track of. The client is responsible for cleanup by passing
 *             the reference back to taiHEN when needed.
 */
typedef uintptr_t tai_hook_ref_t;

/**
 * @brief      Internal structure
 */
struct _tai_hook_user {
  uintptr_t next;
  void *func;
  void *old;
};

/** @name Kernel Hooks
 * Hooks exports to kernel
 */
/** @{ */
SceUID taiHookFunctionAbs(SceUID pid, tai_hook_ref_t *p_hook, void *dest_func, const void *hook_func);
SceUID taiHookFunctionExportForKernel(SceUID pid, tai_hook_ref_t *p_hook, const char *module, uint32_t library_nid, uint32_t func_nid, const void *hook_func);
SceUID taiHookFunctionImportForKernel(SceUID pid, tai_hook_ref_t *p_hook, const char *module, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func);
SceUID taiHookFunctionOffsetForKernel(SceUID pid, tai_hook_ref_t *p_hook, SceUID modid, int segidx, uint32_t offset, int thumb, const void *hook_func);
int taiGetModuleInfoForKernel(SceUID pid, const char *module, tai_module_info_t *info);
int taiHookReleaseForKernel(SceUID tai_uid, tai_hook_ref_t hook);
/** @} */

/** 
 * @name User Hooks
 * Hooks exports to user 
 */
/** @{ */
SceUID taiHookFunctionExportForUser(tai_hook_ref_t *p_hook, tai_hook_args_t *args);
SceUID taiHookFunctionImportForUser(tai_hook_ref_t *p_hook, tai_hook_args_t *args);
SceUID taiHookFunctionOffsetForUser(tai_hook_ref_t *p_hook, tai_offset_args_t *args);
int taiGetModuleInfo(const char *module, tai_module_info_t *info);
int taiHookRelease(SceUID tai_uid, tai_hook_ref_t hook);

/**
 * @brief      Helper function for #taiHookFunctionExportForUser
 *
 *             You can use the macro `TAI_MAIN_MODULE` for `module` to specify
 *             the main module. This is usually the module that is loaded first
 *             and is usually the eboot.bin. This will only work if there is
 *             only one module loaded in the main memory space. Not all
 *             processes have this property! Make sure you check the return
 *             value.
 *
 * @see        taiHookFunctionExportForUser
 *
 * @param[out] p_hook       A reference that can be used by the hook function
 * @param[in]  module       Name of the target module or `TAI_MAIN_MODULE`.
 * @param[in]  library_nid  Optional. NID of the target library.
 * @param[in]  func_nid     The function NID. If `library_nid` is
 *                          `TAI_ANY_LIBRARY`, then the first export with the
 *                          NID will be hooked.
 * @param[in]  hook_func    The hook function
 *
 * @return     { description_of_the_return_value }
 */
HELPER SceUID taiHookFunctionExport(tai_hook_ref_t *p_hook, const char *module, uint32_t library_nid, uint32_t func_nid, const void *hook_func) {
  tai_hook_args_t args;
  args.size = sizeof(args);
  args.module = module;
  args.library_nid = library_nid;
  args.func_nid = func_nid;
  args.hook_func = hook_func;
  return taiHookFunctionExportForUser(p_hook, &args);
}

/**
 * @brief      Helper function for #taiHookFunctionImportForUser
 *
 *             You can use the macro `TAI_MAIN_MODULE` for `module` to specify
 *             the main module. This is usually the module that is loaded first
 *             and is usually the eboot.bin. This will only work if there is
 *             only one module loaded in the main memory space. Not all
 *             processes have this property! Make sure you check the return
 *             value.
 *
 * @see        taiHookFunctionImportForUser
 *
 * @param[out] p_hook              A reference that can be used by the hook
 *                                 function
 * @param[in]  module              Name of the target module or
 *                                 `TAI_MAIN_MODULE`.
 * @param[in]  import_library_nid  The imported library from the target module
 * @param[in]  import_func_nid     The function NID of the import
 * @param[in]  hook_func           The hook function
 */
HELPER SceUID taiHookFunctionImport(tai_hook_ref_t *p_hook, const char *module, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func) {
  tai_hook_args_t args;
  args.size = sizeof(args);
  args.module = module;
  args.library_nid = import_library_nid;
  args.func_nid = import_func_nid;
  args.hook_func = hook_func;
  return taiHookFunctionImportForUser(p_hook, &args);
}

/**
 * @brief      Helper function for #taiHookFunctionOffsetForUser
 *
 * @see        taiHookFunctionOffsetForUser
 *
 * @param[out] p_hook     A reference that can be used by the hook function
 * @param[in]  modid      The module UID from `taiGetModuleInfo`
 * @param[in]  segidx     The ELF segment index containing the function to patch
 * @param[in]  offset     The offset from the start of the segment
 * @param[in]  thumb      Set to 1 if this is a Thumb function
 * @param[in]  hook_func  The hook function (must be in the target address
 *                        space)
 */
HELPER SceUID taiHookFunctionOffset(tai_hook_ref_t *p_hook, SceUID modid, int segidx, uint32_t offset, int thumb, const void *hook_func) {
  tai_offset_args_t args;
  args.size = sizeof(args);
  args.modid = modid;
  args.segidx = segidx;
  args.offset = offset;
  args.thumb = thumb;
  args.source = hook_func;
  return taiHookFunctionOffsetForUser(p_hook, &args);
}
/** @} */

#ifdef __GNUC__
/**
 * @brief      Calls the next function in the chain
 *
 * @param      type  Return type
 * @param      hook  The hook continuing the call
 *
 * @return     Return value from the hook chain
 */
#define TAI_CONTINUE(type, hook, ...) ({ \
  struct _tai_hook_user *cur, *next; \
  cur = (struct _tai_hook_user *)(hook); \
  next = (struct _tai_hook_user *)cur->next; \
  (next == NULL) ? \
    ((type(*)())cur->old)(__VA_ARGS__) \
  : \
    ((type(*)())next->func)(__VA_ARGS__) \
  ; \
})
#else // __GNUC__
#error Non-GCC compatible compilers are currently unsupported
#endif // __GNUC__

/** @} */

/**
 * @defgroup   inject Injection Interface
 * @brief      Inject raw data into a module.
 *
 *             Sometimes, there is a need to inject data directly. This can also
 *             be used to inject code for functions too small to be hooked.
 *             Unlike hooks only one module can patch a given module and given
 *             address at a time. Also note that the original data will be saved
 *             by the kernel. That means huge patches are not recommended!
 */
/** @{ */

/** @name Kernel Injections
 * Injection exports to kernel 
 */
/** @{ */
SceUID taiInjectAbsForKernel(SceUID pid, void *dest, const void *src, size_t size);
SceUID taiInjectDataForKernel(SceUID pid, SceUID modid, int segidx, uint32_t offset, const void *data, size_t size);
int taiInjectReleaseForKernel(SceUID tai_uid);
/** @} */

/** 
 * @name User Injections
 * Injection exports to user 
 */
/** @{ */
SceUID taiInjectAbs(void *dest, const void *src, size_t size);
SceUID taiInjectDataForUser(tai_offset_args_t *args);
int taiInjectRelease(SceUID tai_uid);

/**
 * @brief      Helper function for #taiInjectDataForUser
 *
 * @see        taiInjectDataForUser
 *
 * @param[in]  modid   The module UID from `taiGetModuleInfo`
 * @param[in]  segidx  Index of the ELF segment containing the data to patch
 * @param[in]  offset  The offset from the start of the segment
 * @param[in]  data    The data in kernel address space
 * @param[in]  size    The size of the injection in bytes
 */
HELPER SceUID taiInjectData(SceUID modid, int segidx, uint32_t offset, const void *data, size_t size) {
  tai_offset_args_t args;
  args.size = sizeof(args);
  args.modid = modid;
  args.segidx = segidx;
  args.offset = offset;
  args.source_size = size;
  args.source = data;
  return taiInjectDataForUser(&args);
}
/** @} */

/** @} */

/**
 * @name Plugin loading
 * Kernel plugin loading plugins manually
 */
/** @{ */
int taiLoadPluginsForTitleForKernel(SceUID pid, const char *titleid, int flags);
int taiReloadConfigForKernel(int schedule, int load_kernel);
/** @} */

/**
 * @name Skprx Load
 * Kernel module loading exports to user
 */
/** @{ */

SceUID taiLoadKernelModule(const char *path, int flags, void *opt);
int taiStartKernelModuleForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res);
SceUID taiLoadStartKernelModuleForUser(const char *path, tai_module_args_t *args);
SceUID taiLoadStartModuleForPidForUser(const char *path, tai_module_args_t *args);
int taiStopKernelModuleForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res);
int taiUnloadKernelModule(SceUID modid, int flags, void *opt);
int taiStopUnloadKernelModuleForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res);
int taiStopModuleForPidForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res);
int taiUnloadModuleForPid(SceUID pid, SceUID modid, int flags, void *opt);
int taiStopUnloadModuleForPidForUser(SceUID modid, tai_module_args_t *args, void *opt, int *res);

/**
 * @brief      Helper function for #taiStartKernelModuleForUser
 *
 * @see        taiStartKernelModuleForUser
 *
 * @param[in]  modid  The id from `taiLoadKernelModule`
 * @param[in]  args   The size of the arguments
 * @param      argp   The arguments
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_start`
 */
HELPER int taiStartKernelModule(SceUID modid, int args, void *argp, int flags, void *opt, int *res) {
  tai_module_args_t argg;
  argg.size = sizeof(argg);
  argg.args = args;
  argg.argp = argp;
  argg.flags = flags;
  return taiStartKernelModuleForUser(modid, &argg, opt, res);
}

/**
 * @brief      Helper function for #taiLoadStartKernelModuleForUser
 *
 * @see        taiLoadStartKernelModuleForUser
 *
 * @param[in]  path   The path of the skprx
 * @param[in]  args   The size of the arguments
 * @param      argp   The arguments
 * @param[in]  flags  The flags
 */
HELPER SceUID taiLoadStartKernelModule(const char *path, int args, void *argp, int flags) {
  tai_module_args_t argg;
  argg.size = sizeof(argg);
  argg.args = args;
  argg.argp = argp;
  argg.flags = flags;
  return taiLoadStartKernelModuleForUser(path, &argg);
}

/**
 * @brief      Helper function for #taiLoadStartModuleForPidForUser
 *
 * @see        taiLoadStartModuleForPidForUser
 *
 * @param[in]  pid    The pid to load to
 * @param[in]  path   The path of the suprx
 * @param[in]  args   The size of the arguments
 * @param      argp   The arguments
 * @param[in]  flags  The flags
 */
HELPER SceUID taiLoadStartModuleForPid(SceUID pid, const char *path, int args, void *argp, int flags) {
  tai_module_args_t argg;
  argg.size = sizeof(argg);
  argg.pid = pid;
  argg.args = args;
  argg.argp = argp;
  argg.flags = flags;
  return taiLoadStartModuleForPidForUser(path, &argg);
}

/**
 * @brief      Helper function for #taiStopKernelModuleForUser
 *
 * @see        taiStopKernelModuleForUser
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The size of the arguments to `module_stop`
 * @param      argp   The arguments to `module_stop`
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 */
HELPER int taiStopKernelModule(SceUID modid, int args, void *argp, int flags, void *opt, int *res) {
  tai_module_args_t argg;
  argg.size = sizeof(argg);
  argg.args = args;
  argg.argp = argp;
  argg.flags = flags;
  return taiStopKernelModuleForUser(modid, &argg, opt, res);
}

/**
 * @brief      Helper function for #taiStopUnloadKernelModuleForUser
 *
 * @see        taiStopUnloadKernelModuleForUser
 *
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The size of the arguments to `module_stop`
 * @param      argp   The arguments to `module_stop`
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 */
HELPER int taiStopUnloadKernelModule(SceUID modid, int args, void *argp, int flags, void *opt, int *res) {
  tai_module_args_t argg;
  argg.size = sizeof(argg);
  argg.args = args;
  argg.argp = argp;
  argg.flags = flags;
  return taiStopUnloadKernelModuleForUser(modid, &argg, opt, res);
}

/**
 * @brief      Helper function for #taiStopModuleForPidForUser
 *
 * @see        taiStopModuleForPidForUser
 *
 * @param[in]  pid    The pid
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The size of the arguments to `module_stop`
 * @param      argp   The arguments to `module_stop`
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 */
HELPER int taiStopModuleForPid(SceUID pid, SceUID modid, int args, void *argp, int flags, void *opt, int *res) {
  tai_module_args_t argg;
  argg.size = sizeof(argg);
  argg.pid = pid;
  argg.args = args;
  argg.argp = argp;
  argg.flags = flags;
  return taiStopModuleForPidForUser(modid, &argg, opt, res);
}

/**
 * @brief      Helper function for #taiStopUnloadModuleForPidForUser
 *
 * @see        taiStopUnloadModuleForPidForUser
 *
 * @param[in]  pid    The pid
 * @param[in]  modid  The loaded module reference
 * @param[in]  args   The size of the arguments to `module_stop`
 * @param      argp   The arguments to `module_stop`
 * @param[in]  flags  The flags
 * @param      opt    Optional arguments, set to NULL
 * @param      res    Return value of `module_stop`
 */
HELPER int taiStopUnloadModuleForPid(SceUID pid, SceUID modid, int args, void *argp, int flags, void *opt, int *res) {
  tai_module_args_t argg;
  argg.size = sizeof(argg);
  argg.pid = pid;
  argg.args = args;
  argg.argp = argp;
  argg.flags = flags;
  return taiStopUnloadModuleForPidForUser(modid, &argg, opt, res);
}

/** @} */

/**
 * @name NID Lookup
 * Function NID Lookup Interface
 */
/** @{ */

int taiGetModuleExportFunc(const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

/** @} */

/**
 * @name Peek/Poke
 * Read/write kernel memory (no MMU bypass)
 */
/** @{ */

int taiMemcpyUserToKernel(void *kernel_dst, const void *user_src, size_t len);
int taiMemcpyKernelToUser(void *user_dst, const void *kernel_src, size_t len);

/** @} */

/** @} */

#ifdef __cplusplus
}
#endif

#endif // TAI_HEADER
