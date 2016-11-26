/**
 * @brief      Internal functions and defines
 */
#ifndef TAI_INTERNAL_HEADER
#define TAI_INTERNAL_HEADER

#include <psp2kern/types.h>
#include <inttypes.h>
#include <stdio.h>
#include "taihen.h"
#include "slab.h"

/** For ordering log entries */
extern unsigned char log_ctr;

/** Logging function */
#ifdef ENABLE_LOGGING
#define LOG(fmt, ...) printf("%02X [%s:%d] " fmt "\n", log_ctr++, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOG(fmt, ...)
#endif

/** Max size of a function patch */
#define FUNC_SAVE_SIZE 16

/** Fake PID indicating memory is shared across all user processes. */
#define SHARED_PID 0x80000000

/** Fallback if the current running fw version cannot be detected. */
#define DEFAULT_FW_VERSION 0x3600000

/**
 * @addtogroup patches
 */
/** @{ */

/**
 * Type of patch
 */
typedef enum {
  HOOKS,
  INJECTION
} tai_patch_type_t;

/**
 * @brief      Hook data stored in address space of process to patch
 */
typedef struct _tai_hook {
  struct _tai_hook_user u;      ///< Used by `TAI_CONTINUE` to find next hook to run
  // TODO: obfuscate these two kernel pointers as they might be stored in userland
  // also put a MAC over them
  struct _tai_hook *next;       ///< Next hook for this process + address
  struct _tai_patch *patch;     ///< The patch containing this hook
} tai_hook_t;

/**
 * @brief      Injection data
 */
typedef struct _tai_inject {
  void *saved;                  ///< The original data (allocated on inject)
  size_t size;                  ///< Size of original data
  struct _tai_patch *patch;     ///< The patch containing this injection
} tai_inject_t;

/**
 * @brief      A chain of hooks
 */
typedef struct _tai_hook_list {
  void *func;                   ///< Address of the function to hook
  void *old;                    ///< A function pointer used to call the original function
  void *saved;                  ///< Data saved by libsubstitute to restore the function
  struct _tai_hook *head;       ///< The linked list of hooks on this process + address
} tai_hook_list_t;

/**
 * @brief      A patch containing either a hook chain or an injection
 */
typedef struct _tai_patch {
  uint32_t sce_reserved[2];     ///< used by SCE object system
  union {
    struct _tai_inject inject;  ///< Inject data
    struct _tai_hook_list hooks;///< Hook chain data
  } data;
  tai_patch_type_t type;        ///< Type of patch (hook chain or injection)
  SceUID uid;                   ///< Kernel object id of this object
  SceUID pid;                   ///< Process owning this object
  uintptr_t addr;               ///< Address being patched
  size_t size;                  ///< Size of the patch
  struct _tai_patch *next;      ///< Next patch in the linked list for this process
  struct slab_chain *slab;      ///< Slab chain for this process (copied from the owner `tai_proc_t`)
} tai_patch_t;

/** @} */

/**
 * @addtogroup proc_map
 */
/** @{ */

/**
 * @brief      Internal data for a process
 */
typedef struct _tai_proc {
  SceUID pid;                   ///< Process ID (the key in the map)
  tai_patch_t *head;            ///< Linked list of patches for this process
  struct slab_chain slab;       ///< A slab allocator associated with this process
  struct _tai_proc *next;       ///< Next process in this map bucket
} tai_proc_t;

/** @} */

#endif // TAI_INTERNAL_HEADER
