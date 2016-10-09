/* patches.c -- main patch system
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include "taihen_internal.h"
#include "proc_map.h"

/**
 * @file patches.c
 * @brief      Hooks are added to a linked list and injections are written
 *             directly.
 *
 *             The original code/data is always stored so it can be restored.
 *             The ordering of hooks is not defined and the developer should
 *             expect that the hooks will execute in any order.
 */

/** Size of the heap pool for storing patches and patch metadata in bytes. */
#define PATCHES_POOL_SIZE 0x10000

/** Number of buckets in proc map. */
#define NUM_PROC_MAP_BUCKETS 16

/** Helper macro to make function pointer to data pointer. */
#define FUNC_TO_UINTPTR_T(x) (((uintptr_t)(x))&0xFFFFFFFE)

/** Address range for public (shared) memory. */
#define MEM_SHARED_START ((void*)0xE0000000)

/** PID for kernel process */
#define KERNEL_PID 0x10005

/** Fake PID indicating memory is shared across all user processes. */
#define SHARED_PID 0x0

/** Patches pool resource id */
static SceUID g_patch_pool;

/** The map of processes to list of patches */
static tai_proc_map_t *g_map;

/** Lock for handling hooks */
static SceUID g_hooks_lock;

/**
 * @brief      Initializes the patch system
 * 
 * Requires `proc_map_init` to be called first! Should be called on startup.
 *
 * @return     Zero on success, < 0 on error
 */
int patches_init(void) {
  g_patch_pool = sceKernelMemPoolCreate("tai_patches", PATCHES_POOL_SIZE, NULL);
  if (g_patch_pool < 0) {
    return g_patch_pool;
  } else {
    g_map = proc_map_alloc(NUM_PROC_MAP_BUCKETS);
    if (g_map == NULL) {
      return -1;
    } else {
      g_hooks_lock = sceKernelCreateMutexForKernel("tai_hooks_lock", SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL);
      if (g_hooks_lock < 0) {
        return g_hooks_lock;
      } else {
        return 0;
      }
    }
  }
}

/**
 * @brief      Cleans up the patch system
 * 
 * Should be called before exit.
 */
void patches_deinit(void) {
  sceKernelDeleteMutexForKernel(g_hooks_lock);
  sceKernelMemPoolDestroy(g_patch_pool);
  proc_map_free(g_map);
  g_map = NULL;
  g_patch_pool = 0;
  g_hooks_lock = 0;
}

/**
 * @brief      Adds a hook to a function using libsubstitute
 *
 * @param[in]  pid          The target process
 * @param      target_func  The target function
 * @param[in]  src_func     The source function
 *
 * @return     libsubstitute return value
 */
static int tai_hook_function(SceUID pid, void *target_func, const void *src_func) {
  if (target_func == src_func) {
    return 0; // no need for hook
  }
  return 0;
}

/**
 * @brief      Memcpy within process without the pesky permissions
 *
 *             This function will write raw data from `src` to `dst` for `size`.
 *             It works even if `dst` is read only. All levels of caches will be
 *             flushed.
 *
 * @param[in]  dst_pid  The target process
 * @param      dst      The target address
 * @param[in]  src      The source
 * @param[in]  size     The size
 *
 * @return     Zero on success, < 0 on error
 */
static int tai_force_memcpy(SceUID dst_pid, void *dst, const void *src, size_t size) {
  return 0;
}

/**
 * @brief      Memcpy from a process to kernel
 *
 * @param[in]  src_pid  The source process (can be kernel)
 * @param      dst      The target address
 * @param[in]  src      The source
 * @param[in]  size     The size
 *
 * @return     Zero on success, < 0 on error
 */
static int tai_memcpy_to_kernel(SceUID src_pid, void *dst, const char *src, size_t size) {
  return 0;
}

/**
 * @brief      Adds a hook to a chain, patching the original function if needed
 *
 *             If this is the first hook in a chain, the original function will
 *             be patched. If this hook (same source same destination) is
 *             already in the chain, increment the reference count instead of
 *             adding it.
 *
 * @param      hooks  The chain of hooks to add to
 * @param      item   The hook to add
 * @param      exist  The existing hook (reference counted). Will be same as
 *                    `item` if return 0.
 *
 * @return     Zero if new hook added, 1 hook not added because it exists, < 0
 *             on error
 */
static int hooks_add_hook(tai_hook_list_t *hooks, tai_hook_t *item, tai_hook_t **exist) {
  tai_hook_t *cur;
  int ret;

  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  if (hooks->head == NULL) { // first hook for this list
    hooks->head = item;
    item->next = &hooks->tail;
    ret = tai_hook_function(item->patch->pid, hooks->tail.func, item->func);
  } else {
    for (cur = hooks->head; cur->next != NULL; cur = cur->next) {
      if (cur->patch == item->patch && cur->func == item->func) {
        break;
      }
    }
    if (!(cur->patch == item->patch && cur->func == item->func)) {
      item->next = cur->next;
      cur->next = item;
      cur = item;
      ret = 1;
    } else {
      ret = 0;
    }
    cur->refcnt++;
    *exist = cur;
  }
  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);

  return ret;
}

/**
 * @brief      Removes a hook from a chain, patching the original function if
 *             needed
 *
 *             If the hook to remove is the first hook in a chain, the patched
 *             function will be restored to its original state. If there is
 *             another hook in the chain, the function will be patched again to
 *             jump to that hook.
 *
 * @param      hooks  The chain of hooks to remove from
 * @param      item   The hook to remove
 *
 * @return     Zero on success, < 0 on error or if item is not found
 */
static int hooks_remove_hook(tai_hook_list_t *hooks, tai_hook_t *item) {
  tai_hook_t **cur;
  int ret;

  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  if (hooks->head == item) { // first hook for this list
    // we must remove the patch
    tai_force_memcpy(item->patch->pid, (void *)FUNC_TO_UINTPTR_T(hooks->tail.func), hooks->origcode, hooks->origlen);
    // set head to the next item
    hooks->head = (item->next == &hooks->tail) ? NULL : item->next;
    // add a patch to the new head
    ret = tai_hook_function(item->patch->pid, hooks->tail.func, item->next->func);
  } else {
    cur = &hooks->head;
    ret = -1;
    while (1) {
      if (*cur) {
        if (*cur == item) {
          item->refcnt--;
          if (item->refcnt == 0) {
            *cur = item->next; // remove from list
          }
          ret = 0;
          break;
        } else {
          cur = &(*cur)->next;
        }
      } else {
        break;
      }
    }
  }
  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);
  return ret;
}

/**
 * @brief      Inserts a hook given an absolute address and PID of the function
 *
 * @param[out] p_hook     Outputs the hook if inserted
 * @param[in]  pid        PID of the address space to hook
 * @param      dest_func  The destination function
 * @param[in]  hook_func  The hook function
 *
 * @return     Zero on success, < 0 on error
 */
int taiHookFunctionAbs(tai_hook_t **p_hook, SceUID pid, void *dest_func, const void *hook_func) {
  tai_patch_t *patch, *tmp;
  tai_hook_t *hook;
  int ret;

  if (hook_func >= MEM_SHARED_START) {
    if (pid == KERNEL_PID) {
      return -4; // invalid hook address
    } else {
      pid = SHARED_PID;
    }
  }

  patch = sceKernelMemPoolAlloc(g_patch_pool, sizeof(tai_patch_t));
  if (patch == NULL) {
    return -1;
  }
  hook = sceKernelMemPoolAlloc(g_patch_pool, sizeof(tai_hook_t));
  if (hook == NULL) {
    sceKernelMemPoolFree(g_patch_pool, patch);
    return -1;
  }
  hook->refcnt = 0;

  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  patch->type = HOOKS;
  patch->pid = pid;
  patch->addr = FUNC_TO_UINTPTR_T(dest_func);
  patch->size = FUNC_SAVE_SIZE;
  patch->next = NULL;
  patch->data.hooks.head = NULL;
  patch->data.hooks.tail.next = NULL;
  patch->data.hooks.tail.func = dest_func;
  patch->data.hooks.tail.refcnt = 0;
  tai_memcpy_to_kernel(pid, patch->data.hooks.origcode, (void *)patch->addr, FUNC_SAVE_SIZE);
  patch->data.hooks.origlen = FUNC_SAVE_SIZE;
  if (proc_map_try_insert(g_map, patch, &tmp) < 1) {
    sceKernelMemPoolFree(g_patch_pool, patch);
    if (tmp == NULL || tmp->type != HOOKS) {
      // error
      ret = -2;
      goto err;
    } else {
      // we have an existing patch
      patch = tmp;
    }
  }

  hook->func = (void *)hook_func;
  hook->patch = patch;

  ret = hooks_add_hook(&patch->data.hooks, hook, p_hook);
  if (ret < 0 && patch->data.hooks.head == NULL) {
    *p_hook = NULL;
    proc_map_remove(g_map, patch);
    sceKernelMemPoolFree(g_patch_pool, patch);
  }

err:
  // either hook already exists (refcnt not incremented) or an error
  if (!hook->refcnt) {
    sceKernelMemPoolFree(g_patch_pool, hook);
  }

  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);

  return ret;
}

/**
 * @brief      Removes a hook and restores original function if chain is empty
 *
 * @param      hook  The hook
 *
 * @return     Zero on success, < 0 on error
 */
int taiHookRelease(tai_hook_t *hook) {
  tai_patch_t *patch;
  int ret;

  patch = hook->patch;
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  ret = hooks_remove_hook(&patch->data.hooks, hook);
  if (patch->data.hooks.head == NULL) {
    proc_map_remove(g_map, patch);
    sceKernelMemPoolFree(g_patch_pool, patch);
  }
  if (hook->refcnt == 0) {
    sceKernelMemPoolFree(g_patch_pool, hook);
  }
  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);

  return ret;
}

/**
 * @brief      Inserts a raw data injection given an absolute address and PID of
 *             the address space
 *
 * @param[out] p_inject  Control data for user to keep
 * @param[in]  pid       The pid of the src and dest pointers address space
 * @param      dest      The destination
 * @param[in]  src       The source
 * @param[in]  size      The size
 *
 * @return     Zero on success, < 0 on error
 */
int taiInjectAbs(tai_inject_t **p_inject, SceUID pid, void *dest, const void *src, size_t size) {
  tai_patch_t *patch, *tmp;
  void *saved;
  int ret;

  patch = sceKernelMemPoolAlloc(g_patch_pool, sizeof(tai_patch_t));
  if (patch == NULL) {
    return -1;
  }
  saved = sceKernelMemPoolAlloc(g_patch_pool, size);
  if (saved == NULL) {
    sceKernelMemPoolFree(g_patch_pool, patch);
    return -1;
  }

  // try to save old data
  if (tai_memcpy_to_kernel(pid, saved, dest, size) < 0) {
    sceKernelMemPoolFree(g_patch_pool, patch);
    sceKernelMemPoolFree(g_patch_pool, saved);
    return -3;
  }

  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  patch->type = INJECTION;
  patch->pid = pid;
  patch->addr = (uintptr_t)dest;
  patch->size = size;
  patch->next = NULL;
  patch->data.inject.saved = saved;
  patch->data.inject.size = size;
  patch->data.inject.patch = patch;
  if (proc_map_try_insert(g_map, patch, &tmp) < 1) {
    ret = -2;
  } else {
    *p_inject = &patch->data.inject;
    ret = tai_force_memcpy(pid, dest, src, size);
  }

  if (ret < 0) {
    sceKernelMemPoolFree(g_patch_pool, patch);
    sceKernelMemPoolFree(g_patch_pool, saved);
    *p_inject = NULL;
  }

  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);

  return ret;
}

/**
 * @brief      Removes an injection and restores the original data
 *
 * @param      inject  The injection
 *
 * @return     Zero on success, < 0 on error
 */
int taiInjectRelease(tai_inject_t *inject) {
  tai_patch_t *patch;
  void *saved;
  void *dest;
  size_t size;
  int ret;
  SceUID pid;

  patch = inject->patch;
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  pid = patch->pid;
  dest = (void *)patch->addr;
  saved = inject->saved;
  size = inject->size;
  if (!proc_map_remove(g_map, patch)) {
    ret = -1;
  } else {
    ret = tai_force_memcpy(pid, dest, saved, size);
    sceKernelMemPoolFree(g_patch_pool, saved);
    sceKernelMemPoolFree(g_patch_pool, patch);
  }
  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);

  return ret;
}

/**
 * @brief      Called on process exist to force remove private hooks
 *
 *             It is the caller's responsibilty to clean up before it
 *             terminates! However in the case where that doesn't happen, we try
 *             to salvage the situation by manually freeing all patches for a
 *             PID. This is a dirty free that does not attempt to write back the
 *             original data, so it should only be used at process termination.
 *             THIS NOT NOTE FREE PUBLIC HOOKS! There is no free way of keeping
 *             track of which PIDs have handles to a public hook internally, so
 *             we assume that public hooks stay resident forever unless the
 *             release call is made by the caller.
 *
 * @param[in]  pid   The pid
 *
 * @return     Zero always
 */
int taiTryCleanupProcess(SceUID pid) {
  tai_patch_t *patch, *next;
  tai_hook_t *hook, *nexthook;
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  if (proc_map_remove_all_pid(g_map, pid, &patch) > 0) {
    while (patch != NULL) {
      next = patch->next;
      if (patch->type == HOOKS) {
        hook = patch->data.hooks.head;
        while (hook != &patch->data.hooks.tail && hook != NULL) {
          nexthook = hook->next;
          hook->refcnt--;
          if (hook->refcnt == 0) {
            sceKernelMemPoolFree(g_patch_pool, hook);
          }
          hook = nexthook;
        }
      }
      sceKernelMemPoolFree(g_patch_pool, patch);
      patch = next;
    }
  }
  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);
  return 0;
}
