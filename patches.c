/* patches.c -- main patch system
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <string.h>
#include "error.h"
#include "taihen_internal.h"
#include "proc_map.h"
#include "slab.h"
#include "substitute/lib/substitute.h"

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

/** Patches pool resource id. Also used in posix-compat.c */
SceUID g_patch_pool;

/** The map of processes to list of patches */
static tai_proc_map_t *g_map;

/** Lock for handling hooks */
static SceUID g_hooks_lock;

/** UID class for taiHEN */
static SceClass g_taihen_class;

/**
 * @brief      Does nothing. Used as a callback.
 *
 * @param      dat   Unused
 *
 * @return     Zero
 */
static int nop_func(void *dat) {
  return 0;
}

/**
 * @brief      Initializes the patch system
 * 
 * Requires `proc_map_init` to be called first! Should be called on startup.
 *
 * @return     Zero on success, < 0 on error
 */
int patches_init(void) {
  int ret;

  g_patch_pool = sceKernelMemPoolCreate("tai_patches", PATCHES_POOL_SIZE, NULL);
  LOG("sceKernelMemPoolCreate(tai_patches): 0x%08X", g_patch_pool);
  if (g_patch_pool < 0) {
    return g_patch_pool;
  }
  g_map = proc_map_alloc(NUM_PROC_MAP_BUCKETS);
  if (g_map == NULL) {
    LOG("Failed to create proc map.");
    return TAI_ERROR_SYSTEM;
  }
  g_hooks_lock = sceKernelCreateMutexForKernel("tai_hooks_lock", SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL);
  LOG("sceKernelCreateMutexForKernel(tai_hooks_lock): 0x%08X", g_hooks_lock);
  if (g_hooks_lock < 0) {
    return g_hooks_lock;
  }
  ret = sceKernelCreateClass(&g_taihen_class, "taiHENClass", sceKernelGetUidClass(), sizeof(tai_patch_t), nop_func, nop_func);
  LOG("sceKernelCreateClass(taiHENClass): 0x%08X", ret);
  if (ret < 0) {
    return ret;
  }
  return TAI_SUCCESS;
}

/**
 * @brief      Cleans up the patch system
 * 
 * Should be called before exit.
 */
void patches_deinit(void) {
  LOG("Cleaning up patches subsystem.");
  // TODO: Find out how to clean up class
  sceKernelDeleteMutexForKernel(g_hooks_lock);
  sceKernelMemPoolDestroy(g_patch_pool);
  proc_map_free(g_map);
  g_map = NULL;
  g_patch_pool = 0;
  g_hooks_lock = 0;
}

/**
 * @brief      Flush L1 and L2 cache for an address
 *
 * @param[in]  pid   The pid
 * @param[in]  vma   The vma
 * @param[in]  len   The length
 */
void mirror_cache_flush(SceUID pid, uintptr_t vma, size_t len) {
  uintptr_t vma_align;
  int flags;
  int context[3];
  int ret;

  vma_align = vma & ~0x1F;
  len = ((vma + len + 0x1F) & ~0x1F) - vma_align;

  flags = sceKernelCpuDisableInterrupts();
  sceKernelCpuSaveContext(context);
  ret = sceKernelSwitchVmaForPid(pid);
  sceKernelCpuDcacheAndL2Flush((void *)vma_align, len);
  sceKernelCpuIcacheAndL2Flush((void *)vma_align, len);
  sceKernelCpuRestoreContext(context);
  sceKernelCpuEnableInterrupts(flags);
  LOG("sceKernelSwitchVmaForPid(%d): 0x%08X\n", pid, ret);
}

/**
 * @brief      Adds a hook to a function using libsubstitute
 *
 * @param      slab         The slab to allocate exec memory from
 * @param      target_func  The function to hook
 * @param[in]  src_func     The hook function
 * @param      old          A pointer to call the original implementation
 * @param      saved        Saved data for freeing the hook
 *
 * @return     Zero on success, < 0 on error
 */
static int tai_hook_function(struct slab_chain *slab, void *target_func, const void *src_func, void **old, void **saved) {
  struct substitute_function_hook hook;
  int ret;

  if (target_func == src_func) {
    LOG("no hook needed");
    return TAI_SUCCESS; // no need for hook
  }

  hook.function = target_func;
  hook.replacement = (void *)src_func;
  hook.old_ptr = old;
  hook.options = 0;
  hook.opt = slab;
  ret = substitute_hook_functions(&hook, 1, (struct substitute_function_hook_record **)saved, 0);
  if (ret != SUBSTITUTE_OK) {
    LOG("libsubstitute error: %s", substitute_strerror(ret));
    return TAI_ERROR_SYSTEM;
  }
  return TAI_SUCCESS;
}

/**
 * @brief      Removes a hook using libsubstitute
 *
 * @param[in]  saved  The saved data from `tai_hook_function`
 *
 * @return     Zero on success, < 0 on error
 */
static int tai_unhook_function(void *saved) {
  int ret;
  ret = substitute_free_hooks((struct substitute_function_hook_record *)saved, 1);
  if (ret != SUBSTITUTE_OK) {
    LOG("libsubstitute error: %s", substitute_strerror(ret));
    return TAI_ERROR_SYSTEM;
  }
  return TAI_SUCCESS;
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
 * @param[in]  src      The source kernel address
 * @param[in]  size     The size
 *
 * @return     Zero on success, < 0 on error
 */
static int tai_force_memcpy(SceUID dst_pid, void *dst, const void *src, size_t size) {
  int ret;
  if (dst_pid == KERNEL_PID) {
      ret = sceKernelCpuUnrestrictedMemcpy(dst, src, size);
      LOG("sceKernelCpuUnrestrictedMemcpy(0x%p, 0x%p, 0x%08X): 0x%08X", dst, src, size, ret);
  } else {
      ret = sceKernelRxMemcpyKernelToUserForPid(dst_pid, (uintptr_t)dst, src, size);
      LOG("sceKernelRxMemcpyKernelToUserForPid(%d, 0x%p, 0x%p, 0x%08X): 0x%08X", dst_pid, dst, src, size, ret);
  }
  sceKernelCpuDcacheAndL2Flush(dst, size);
  return ret;
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
  int ret;
  if (src_pid == KERNEL_PID) {
    memcpy(dst, src, size);
    LOG("memcpy(0x%p, 0x%p, 0x%08X)", dst, src, size);
  } else {
    ret = sceKernelMemcpyUserToKernelForPid(src_pid, dst, (uintptr_t)src, size);
    LOG("sceKernelMemcpyUserToKernelForPid(%d, 0x%p, 0x%p, 0x%08X): 0x%08X", src_pid, dst, src, size, ret);
  }
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

  LOG("Adding hook %p to chain %p", item, hooks);
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  if (hooks->head == NULL) { // first hook for this list
    hooks->head = item;
    item->next = NULL;
    ret = tai_hook_function(item->patch->slab, hooks->func, item->func, &hooks->old, &hooks->saved);
    item->old = hooks->old;
    mirror_cache_flush(item->patch->pid, slab_getmirror(item->patch->slab, item), sizeof(tai_hook_t));
  } else {
    for (cur = hooks->head; cur->next != NULL; cur = cur->next) {
      if (cur->patch == item->patch && cur->func == item->func) {
        break;
      }
    }
    if (!(cur->patch == item->patch && cur->func == item->func)) {
      item->next = cur->next;
      item->next_user = cur->next_user;
      item->old = hooks->old;
      cur->next = item;
      cur->next_user = slab_getmirror(item->patch->slab, item);
      // flush cache
      mirror_cache_flush(item->patch->pid, slab_getmirror(item->patch->slab, cur), sizeof(tai_hook_t));
      mirror_cache_flush(item->patch->pid, cur->next_user, sizeof(tai_hook_t));
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
  uintptr_t tmp, *cur_user;
  int ret;

  LOG("Removing hook %p for %p", item, hooks);
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  if (hooks->head == item) { // first hook for this list
    // we must remove the patch
    tai_unhook_function(item->patch->data.hooks.saved);
    // set head to the next item
    hooks->head = item->next;
    // add a patch to the new head
    ret = tai_hook_function(item->patch->slab, hooks->func, item->next->func, &hooks->old, &hooks->saved);
    // update the old pointers
    for (cur = &hooks->head; *cur != NULL; cur = &(*cur)->next) {
      (*cur)->old = hooks->old;
    }
    // clear cache of mirror for the last item since it uses the old pointer
    mirror_cache_flush(item->patch->pid, (uintptr_t)cur - offsetof(tai_hook_t, next), sizeof(tai_hook_t));
  } else {
    cur = &hooks->head;
    cur_user = &tmp;
    ret = -1;
    while (1) {
      if (*cur) {
        if (*cur == item) {
          item->refcnt--;
          if (item->refcnt == 0) {
            *cur = item->next; // remove from list
            *cur_user = item->next_user;
            // clear cache
            mirror_cache_flush(item->patch->pid, (uintptr_t)cur - offsetof(tai_hook_t, next), sizeof(tai_hook_t));
          }
          ret = 0;
          break;
        } else {
          cur = &(*cur)->next;
          cur_user = &(*cur)->next_user;
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
 * @param[out] p_hook     Outputs a reference object if successful
 * @param[in]  pid        PID of the address space to hook
 * @param      dest_func  The destination function
 * @param[in]  hook_func  The hook function
 *
 * @return     UID for the hook on success, < 0 on error
 */
SceUID tai_hook_func_abs(tai_hook_ref_t *p_hook, SceUID pid, void *dest_func, const void *hook_func) {
  tai_patch_t *patch, *tmp;
  tai_hook_t *hook, *inserted;
  SceUID uid;
  int ret;
  struct slab_chain *slab;
  uintptr_t exe_addr;

  LOG("Hooking 0x%p to 0x%p for pid %d", hook_func, dest_func, pid);
  if (hook_func >= MEM_SHARED_START) {
    if (pid == KERNEL_PID) {
      return TAI_ERROR_INVALID_KERNEL_ADDR; // invalid hook address
    } else {
      pid = SHARED_PID;
    }
  }

  hook = NULL;
  ret = sceKernelCreateUidObj(&g_taihen_class, "tai_patch_hook", NULL, (void **)&patch);
  LOG("sceKernelCreateUidObj(tai_patch_hook): 0x%08X, %p", ret, patch);
  if (ret < 0) {
    return ret;
  }

  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  patch->type = HOOKS;
  patch->uid = ret;
  patch->pid = pid;
  patch->addr = FUNC_TO_UINTPTR_T(dest_func);
  patch->size = FUNC_SAVE_SIZE;
  patch->next = NULL;
  patch->data.hooks.func = dest_func;
  patch->data.hooks.saved = NULL;
  patch->data.hooks.head = NULL;
  if (proc_map_try_insert(g_map, patch, &tmp) < 1) {
    ret = sceKernelDeleteUid(patch->uid);
    LOG("sceKernelDeleteUid(0x%08X): 0x%08X", patch->uid, ret);
    if (tmp == NULL || tmp->type != HOOKS) {
      // error
      LOG("internal error: proc_map cannot insert hook but did not return a valid existing hook");
      ret = TAI_ERROR_SYSTEM;
      goto err;
    } else {
      // we have an existing patch
      LOG("found existing patch %p, discarding %p", tmp, patch);
      patch = tmp;
    }
  }

  slab = patch->slab;
  hook = slab_alloc(slab, &exe_addr);
  if (hook == NULL) {
    ret = -1;
    goto err;
  }
  hook->refcnt = 0;
  hook->func = (void *)hook_func;
  hook->patch = patch;

  inserted = NULL;
  ret = hooks_add_hook(&patch->data.hooks, hook, &inserted);
  if (ret < 0 && patch->data.hooks.head == NULL) {
    LOG("failed to add hook and patch is now empty, freeing it");
    proc_map_remove(g_map, patch);
    sceKernelDeleteUid(patch->uid);
  }
  if (ret >= 0) {
    ret = patch->uid;
    *p_hook = slab_getmirror(slab, inserted);
  }

err:
  // either hook already exists (refcnt not incremented) or an error
  if (hook && !hook->refcnt) {
    slab_free(slab, hook);
  }

  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);

  return ret;
}

/**
 * @brief      Removes a hook and restores original function if chain is empty
 *
 * @param[in]  uid       The uid reference
 * @param[in]  hook_ref  The hook
 *
 * @return     Zero on success, < 0 on error
 */
int tai_hook_release(SceUID uid, tai_hook_ref_t hook_ref) {
  tai_hook_t *hook;
  tai_patch_t *patch;
  struct slab_chain *slab;
  int ret;

  ret = sceKernelGetObjForUid(uid, &g_taihen_class, (void **)&patch);
  LOG("sceKernelGetObjForUid(%d): 0x%08X", uid, ret);
  if (ret < 0) {
    return ret;
  }
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  slab = patch->slab;
  for (hook = patch->data.hooks.head; hook != NULL; hook = hook->next) {
    if (slab_getmirror(slab, hook) == hook_ref) {
      LOG("Found hook %p for ref %p", hook, hook_ref);
      ret = hooks_remove_hook(&patch->data.hooks, hook);
      if (patch->data.hooks.head == NULL) {
        LOG("patch is now empty, freeing it");
        proc_map_remove(g_map, patch);
        sceKernelDeleteUid(patch->uid);
      }
      if (hook->refcnt == 0) {
        LOG("hook is no longer referenced, freeing it");
        slab_free(slab, hook);
      }
      ret = TAI_SUCCESS;
      goto end;
    }
  }
  LOG("Cannot find hook for uid %d ref %p", uid, hook_ref);
  ret = TAI_ERROR_NOT_FOUND;
end:
  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);

  return ret;
}

/**
 * @brief      Inserts a raw data injection given an absolute address and PID of
 *             the address space
 *
 * @param[in]  pid   The pid of the src and dest pointers address space
 * @param      dest  The destination
 * @param[in]  src   The source
 * @param[in]  size  The size
 *
 * @return     UID for the injection on success, < 0 on error
 *             - TAI_ERROR_PATCH_EXISTS if a hook or injection is already
 *               inserted
 */
SceUID tai_inject_abs(SceUID pid, void *dest, const void *src, size_t size) {
  tai_patch_t *patch, *tmp;
  void *saved;
  int ret;

  LOG("Injecting 0x%p with 0x%p for size 0x%08X at pid %d", dest, src, size, pid);
  ret = sceKernelCreateUidObj(&g_taihen_class, "tai_patch_inject", NULL, (void **)&patch);
  LOG("sceKernelCreateUidObj(tai_patch_inject): 0x%08X, 0x%p", ret, ret, patch);
  if (ret < 0) {
    return ret;
  }
  saved = sceKernelMemPoolAlloc(g_patch_pool, size);
  LOG("sceKernelMemPoolAlloc(g_patch_pool, 0x%08X): 0x%p", size, saved);
  if (saved == NULL) {
    sceKernelDeleteUid(ret);
    return TAI_ERROR_MEMORY;
  }

  // try to save old data
  if (tai_memcpy_to_kernel(pid, saved, dest, size) < 0) {
    LOG("Invalid address for memcpy");
    sceKernelDeleteUid(ret);
    sceKernelMemPoolFree(g_patch_pool, saved);
    return TAI_ERROR_INVALID_ARGS;
  }

  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  patch->type = INJECTION;
  patch->uid = ret;
  patch->pid = pid;
  patch->addr = (uintptr_t)dest;
  patch->size = size;
  patch->next = NULL;
  patch->data.inject.saved = saved;
  patch->data.inject.size = size;
  patch->data.inject.patch = patch;
  if (proc_map_try_insert(g_map, patch, &tmp) < 1) {
    ret = TAI_ERROR_PATCH_EXISTS;
  } else {
    ret = tai_force_memcpy(pid, dest, src, size);
  }

  if (ret < 0) {
    sceKernelDeleteUid(patch->uid);
    sceKernelMemPoolFree(g_patch_pool, saved);
  } else {
    ret = patch->uid;
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
int tai_inject_release(SceUID uid) {
  tai_inject_t *inject;
  tai_patch_t *patch;
  void *saved;
  void *dest;
  size_t size;
  int ret;
  SceUID pid;

  ret = sceKernelGetObjForUid(uid, &g_taihen_class, (void **)&patch);
  LOG("sceKernelGetObjForUid(%d): 0x%08X", uid, ret);
  if (ret < 0) {
    return ret;
  }
  if (patch->type != INJECTION || patch->uid != uid) {
    LOG("internal error: trying to free an invalid injection");
    return TAI_ERROR_SYSTEM;
  }
  inject = &patch->data.inject;
  LOG("Releasing injection %p for patch %p", inject, patch);
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  pid = patch->pid;
  dest = (void *)patch->addr;
  saved = inject->saved;
  size = inject->size;
  if (!proc_map_remove(g_map, patch)) {
    LOG("internal error, cannot remove patch from proc_map");
    ret = TAI_ERROR_SYSTEM;
  } else {
    ret = tai_force_memcpy(pid, dest, saved, size);
    sceKernelMemPoolFree(g_patch_pool, saved);
    sceKernelDeleteUid(patch->uid);
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
int tai_try_cleanup_process(SceUID pid) {
  tai_patch_t *patch, *next;
  tai_hook_t *hook, *nexthook;
  LOG("Calling patches cleanup for pid %d", pid);
  sceKernelLockMutexForKernel(g_hooks_lock, 1, NULL);
  if (proc_map_remove_all_pid(g_map, pid, &patch) > 0) {
    while (patch != NULL) {
      next = patch->next;
      if (patch->type == HOOKS) {
        hook = patch->data.hooks.head;
        while (hook != NULL) {
          nexthook = hook->next;
          hook->refcnt--;
          if (hook->refcnt == 0) {
            slab_free(patch->slab, hook);
          }
          hook = nexthook;
        }
      }
      sceKernelDeleteUid(patch->uid);
      patch = next;
    }
  }
  sceKernelUnlockMutexForKernel(g_hooks_lock, 1);
  return 0;
}
