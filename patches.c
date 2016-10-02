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

/** Patches pool resource id */
static SceUID g_patch_pool;

/** The map of processes to list of patches */
static tai_proc_map_t *g_map;

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
      return 0;
    }
  }
}

/**
 * @brief      Cleans up the patch system
 * 
 * Should be called before exit.
 */
void patches_deinit(void) {
  sceKernelMemPoolDestroy(g_patch_pool);
  proc_map_free(g_map);
  g_map = NULL;
  g_patch_pool = 0;
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
 * If this is the first hook in a chain, the original function will be patched.
 *
 * @param      hooks  The chain of hooks to add to
 * @param      item   The hook to add
 *
 * @return     Zero on success, < 0 on error
 */
static int hooks_add_hook(tai_hook_list_t *hooks, tai_hook_t *item) {
  int ret;

  sceKernelLockMutexForKernel(hooks->lock, 1, NULL);
  if (hooks->head == NULL) { // first hook for this list
    hooks->head = item;
    item->next = &hooks->tail;
    ret = tai_hook_function(item->patch->pid, hooks->tail.func, item->func);
  } else {
    item->next = hooks->head->next;
    hooks->head->next = item->next;
    ret = 0;
  }
  sceKernelUnlockMutexForKernel(hooks->lock, 1);

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

  sceKernelLockMutexForKernel(hooks->lock, 1, NULL);
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
          *cur = item->next;
          ret = 0;
          break;
        }
      } else {
        break;
      }
    }
  }
  sceKernelUnlockMutexForKernel(hooks->lock, 1);
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
  int cleanup;

  patch = sceKernelMemPoolAlloc(g_patch_pool, sizeof(tai_patch_t));
  hook = sceKernelMemPoolAlloc(g_patch_pool, sizeof(tai_hook_t));
  if (hook == NULL || patch == NULL) {
    return -1;
  }

  patch->type = HOOKS;
  patch->pid = pid;
  patch->addr = FUNC_TO_UINTPTR_T(dest_func);
  patch->size = FUNC_SAVE_SIZE;
  patch->next = NULL;
  patch->data.hooks.lock = sceKernelCreateMutexForKernel("tai_hooks", SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL);
  patch->data.hooks.head = NULL;
  patch->data.hooks.tail.next = NULL;
  patch->data.hooks.tail.func = dest_func;
  tai_memcpy_to_kernel(pid, patch->data.hooks.origcode, (void *)patch->addr, FUNC_SAVE_SIZE);
  patch->data.hooks.origlen = FUNC_SAVE_SIZE;
  if (proc_map_try_insert(g_map, patch, &tmp) < 1) {
    sceKernelDeleteMutexForKernel(patch->data.hooks.lock);
    sceKernelMemPoolFree(g_patch_pool, patch);
    if (tmp == NULL || tmp->type != HOOKS) {
      // error
      sceKernelMemPoolFree(g_patch_pool, hook);
      return -2;
    } else {
      // we have an existing patch
      patch = tmp;
    }
  }

  hook->func = (void *)hook_func;
  hook->patch = patch;
  *p_hook = hook;

  sceKernelLockMutexForKernel(patch->data.hooks.lock, 1, NULL);
  ret = hooks_add_hook(&patch->data.hooks, hook);
  cleanup = 0;
  if (patch->data.hooks.head == NULL) {
    proc_map_remove(g_map, patch);
    cleanup = 1;
  }
  sceKernelUnlockMutexForKernel(patch->data.hooks.lock, 1);

  // we removed from the map
  if (cleanup) {
    sceKernelDeleteMutexForKernel(patch->data.hooks.lock);
    sceKernelMemPoolFree(g_patch_pool, patch);
  }

  // error adding hook
  if (ret < 0) {
    sceKernelMemPoolFree(g_patch_pool, hook);
  }

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
  int cleanup;

  patch = hook->patch;
  sceKernelLockMutexForKernel(patch->data.hooks.lock, 1, NULL);
  ret = hooks_remove_hook(&patch->data.hooks, hook);
  cleanup = 0;
  if (patch->data.hooks.head == NULL) {
    proc_map_remove(g_map, patch);
    cleanup = 1;
  }
  sceKernelUnlockMutexForKernel(patch->data.hooks.lock, 1);

  // we removed from the map
  if (cleanup) {
    sceKernelDeleteMutexForKernel(patch->data.hooks.lock);
    sceKernelMemPoolFree(g_patch_pool, patch);
  }

  sceKernelMemPoolFree(g_patch_pool, hook);

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
  int cleanup;

  patch = sceKernelMemPoolAlloc(g_patch_pool, sizeof(tai_patch_t));
  saved = sceKernelMemPoolAlloc(g_patch_pool, size);
  if (patch == NULL || saved == NULL) {
    return -1;
  }

  // try to save old data
  if (tai_memcpy_to_kernel(pid, saved, dest, size) < 0) {
    sceKernelMemPoolFree(g_patch_pool, patch);
    sceKernelMemPoolFree(g_patch_pool, saved);
    return -3;
  }

  patch->type = INJECTION;
  patch->pid = pid;
  patch->addr = (uintptr_t)dest;
  patch->size = size;
  patch->next = NULL;
  patch->data.inject.saved = saved;
  patch->data.inject.size = size;
  patch->data.inject.patch = patch;
  if (proc_map_try_insert(g_map, patch, &tmp) < 1) {
    sceKernelMemPoolFree(g_patch_pool, patch);
    sceKernelMemPoolFree(g_patch_pool, saved);
    return -2;
  }

  *p_inject = &patch->data.inject;
  ret = tai_force_memcpy(pid, dest, src, size);
  if (ret < 0) {
    taiInjectRelease(*p_inject);
    *p_inject = NULL;
  }

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
  pid = patch->pid;
  dest = (void *)patch->addr;
  saved = inject->saved;
  size = inject->size;
  if (!proc_map_remove(g_map, patch)) {
    return -1;
  } else {
    ret = tai_force_memcpy(pid, dest, saved, size);
    sceKernelMemPoolFree(g_patch_pool, saved);
  }

  return ret;
}
