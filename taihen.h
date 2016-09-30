/**
 * @brief      CFW framework for Vita
 */
#ifndef TAI_HEADER
#define TAI_HEADER

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * @defgroup   plugin Plugin Support Interface
 * @brief      Provides basic helper utilities for plugins that aid in user to
 *             kernel interaction.
 */
/** @{ */

/**
 * @brief      Plugin start arguments
 *
 *             This structure is passed from taiHEN to the user plugin being
 *             loaded in `module_start`. Kernel plugins have user defined
 *             arguments and does not get this struct!
 */
typedef struct {
  uint32_t size;
  uint32_t library_nid;
} tai_start_t;

/** @} */

/**
 * @defgroup   hooks Hooks Interface
 * @brief      Hook imports and export functions. Allows multiple plugins to
 *             hook a single function.
 */
/** @{ */

/**
 * \brief Hook information
 * 
 * This reference is created on new hooks and is up to the caller to keep track
 * of. The client is responsible for cleanup by passing the reference back to
 * taiHEN when needed.
 */
typedef struct _tai_hook tai_hook_t;

int taiHookFunctionExport(tai_hook_t **p_hook, SceUID pid, uint32_t library_nid, uint32_t func_nid, const void *hook_func);
int taiHookFunctionImport(tai_hook_t **p_hook, SceUID pid, uint32_t target_library_nid, uint32_t import_library_nid, uint32_t import_func_nid, const void *hook_func);
int taiHookFunctionOffset(tai_hook_t **p_hook, SceUID pid, uint32_t module_nid, int segidx, uint32_t offset, int thumb, const void *hook_func);
int taiHookContinue(tai_hook_t *hook, ...);
int taiHookRelease(tai_hook_t *hook);

/**
 * @brief      Convenience function for calling `taiHookContinue`
 *
 * @param      type  Return type
 * @param      hook  The hook continuing the call
 * @param      args  The arguments to the call
 *
 * @return     Return value from the hook chain
 */
#define TAI_CONTINUE(type, hook, args...) ((type)taiHookContinue(hook, args))

/** @} */

/**
 * @defgroup   inject Injection Interface
 * @brief      Inject raw data into a module.
 *
 *             Sometimes, there is a need to inject data directly. This can also
 *             be used to inject code for functions too small to be hooked.
 *             Unlike hooks only one module can patch a given module and given
 *             address at a time.
 */
/** @{ */

/**
 * @brief      Injection information
 *
 *             The original data being patched will be stored in memory. That
 *             means huge patches are not recommended! This reference is kept by
 *             the caller for clean up purposes.
 */
typedef struct _tai_inject tai_inject_t;

int taiInjectData(tai_inject_t *p_inject, uint32_t module_nid, int segidx, uint32_t offset, const void *data, size_t len);
int taiInjectRelease(tai_inject_t *p_inject);

/** @} */

/**
 * @defgroup   skprx Skprx Loading Interface
 * @brief      Allows user modules to load kernel modules.
 *
 *             Only accessable to non-safe homebrew and taiHEN plugins.
 */
/** @{ */

int taiLoadKernelModule(const char *path, int flags, int *opt);
int taiStartKernelModule(int modid, int argc, void *args, int flags, void *opt, int *res);
int taiLoadStartKernelModule(const char *path, int argc, void *args, int flags);
int taiStopUnloadKernelModule(int modid, int argc, void *args, int flags, void *opt, int *res);
int taiUnloadKernelModule(int modid, int flags);

/** @} */

/**
 * @defgroup   skprx Kernel Memory Interface
 * @brief      Allows user modules to peek/poke the kernel.
 *
 *             Only accessable to non-safe homebrew and taiHEN plugins. Does not
 *             bypass MMU restrictions (you cannot write to code pages).
 */
/** @{ */

int taiMemcpyUserToKernel(void *kernel_dst, const void *user_src, size_t len);
int taiMemcpyKernelToUser(void *user_dst, const void *kernel_src, size_t len);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // TAI_HEADER
