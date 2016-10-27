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
#define TAI_ANY_LIBRARY 0

/**
 * @brief      Plugin start arguments
 *
 *             This structure is passed from taiHEN to the user plugin being
 *             loaded in `module_start`. Kernel plugins have user defined
 *             arguments and does not get this struct!
 */
typedef struct _tai_start {
  uint32_t size;
  uint32_t library_nid;
} tai_start_t;

/**
 * @brief      Extended module information
 *
 *             This supplements the output of `sceKernelGetModuleInfo`
 */
typedef struct _tai_module_info {
  size_t size;
  SceUID modid;
  uint32_t module_nid;
  const char *name;
  uintptr_t exports_start;
  uintptr_t exports_end;
  uintptr_t imports_start;
  uintptr_t imports_end;
} tai_module_info_t;

/**
 * @defgroup   hook Hooks Interface
 * @brief      Patches functions.
 *
 *  A function hook allows a plugin to run code before and after a
 *  any function call. As an example, say we wish to hook
 *  `sceIoOpen`
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
 *      fd = sceIoOpen(log, SCE_O_WRONLY, 0);
 *      sceIoWrite(fd, path, 256);
 *      sceIoClose(fd);
 *    }
 *    return ret;
 *  }
 *  ```
 *
 *  Note that calling the original `sceIoOpen` will recurse
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

#ifdef __VITA_KERNEL__
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
#endif // __VITA_KERNEL__

/** 
 * @name User Hooks
 * Hooks exports to user 
 */
/** @{ */
SceUID taiHookFunctionExport(tai_hook_ref_t *p_hook, const char *module, uint32_t library_nid, uint32_t func_nid, const void *hook_func);
SceUID taiHookFunctionImport(tai_hook_ref_t *p_hook, const char *module, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func);
SceUID taiHookFunctionOffset(tai_hook_ref_t *p_hook, SceUID modid, int segidx, uint32_t offset, int thumb, const void *hook_func);
int taiGetModuleInfo(const char *module, tai_module_info_t *info);
int taiHookRelease(SceUID tai_uid, tai_hook_ref_t hook);
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

#ifdef __VITA_KERNEL__
/** @name Kernel Injections
 * Injection exports to kernel 
 */
/** @{ */
SceUID taiInjectAbsForKernel(SceUID pid, void *dest, const void *src, size_t size);
SceUID taiInjectDataForKernel(SceUID pid, SceUID modid, int segidx, uint32_t offset, const void *data, size_t size);
int taiInjectReleaseForKernel(SceUID tai_uid);
/** @} */
#endif // !__VITA_KERNEL__

/** 
 * @name User Injections
 * Injection exports to user 
 */
/** @{ */
SceUID taiInjectAbs(void *dest, const void *src, size_t size);
SceUID taiInjectData(SceUID modid, int segidx, uint32_t offset, const void *data, size_t size);
int taiInjectRelease(SceUID tai_uid);
/** @} */

/** @} */

/**
 * @name Skprx Load
 * Kernel module loading exports to user
 */
/** @{ */

SceUID taiLoadKernelModule(const char *path, int flags, int *opt);
int taiStartKernelModule(SceUID modid, int argc, void *args, int flags, void *opt, int *res);
SceUID taiLoadStartKernelModule(const char *path, int argc, void *args, int flags);
int taiStopUnloadKernelModule(SceUID modid, int argc, void *args, int flags, void *opt, int *res);
int taiUnloadKernelModule(SceUID modid, int flags);

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
