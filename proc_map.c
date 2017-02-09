/* proc_map.c -- map structure for organizing patches
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <string.h>
#include "taihen_internal.h"
#include "proc_map.h"
#include "slab.h"

/**
 * @brief      Patches are grouped by PID and stored in a linked list ordered by
 *             the address being patched. The groups are stored in a hash map
 *             where the hash function is just the PID.
 */

/** Size of the heap pool for storing the map in bytes. */
#define MAP_POOL_SIZE 1024

/** Found in substitute/lib/vita/execmem.c **/
extern const size_t g_exe_slab_item_size;

/** Resource pointer for the heap pool */
static SceUID g_map_pool;

/**
 * @brief      Initializes the map system
 *
 *             Must be called on startup.
 *
 * @return     Zero on success or memory allocation error code.
 */
int proc_map_init(void) {
  SceKernelHeapCreateOpt opt;
  memset(&opt, 0, sizeof(opt));
  opt.size = sizeof(opt);
  opt.uselock = 1;
  g_map_pool = ksceKernelCreateHeap("tai_maps", MAP_POOL_SIZE, &opt);
  if (g_map_pool < 0) {
    return g_map_pool;
  } else {
    return 0;
  }
}

/**
 * @brief      Cleans up the map system
 *
 *             Should be called before exit.
 */
void proc_map_deinit(void) {
  ksceKernelDeleteHeap(g_map_pool);
  g_map_pool = 0;
}

/**
 * @brief      Allocates a new map
 *
 * @param[in]  nbuckets  The number of buckets for the map.
 *
 * @return     Pointer to an allocated map structure on success. Null on
 *             failure.
 */
tai_proc_map_t *proc_map_alloc(int nbuckets) {
  tai_proc_map_t *map;

  map = ksceKernelAllocHeapMemory(g_map_pool, sizeof(tai_proc_map_t) + sizeof(tai_proc_t *) * nbuckets);
  if (map == NULL) {
    return NULL;
  }
  map->nbuckets = nbuckets;
  map->lock = ksceKernelCreateMutex("tai_map", SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL);
  for (int i = 0; i < nbuckets; i++) {
    map->buckets[i] = NULL;
  }
  return map;
}

/**
 * @brief      Frees a map
 *
 * @param      map   The map
 */
void proc_map_free(tai_proc_map_t *map) {
  ksceKernelDeleteMutex(map->lock);
  ksceKernelFreeHeapMemory(g_map_pool, map);
}

/**
 * @brief      Inserts into the map if no overlap or get patch that completely
 *             overlaps
 *
 *             If there is no overlap with any other element for a given PID,
 *             then insert the patch into the map. If there is overlap, the
 *             function will return zero and not insert the patch. If the
 *             overlap is complete (same address and size), then this will
 *             return a pointer to the overlapping patch also.
 *
 * @param      map       The map
 * @param[in]  patch     The patch to attempt insert
 * @param[out] existing  If and only if there exists a patch with the same
 *                       address and size, then the function returns zero and
 *                       this pointer will be set to the patch that overlaps.
 *                       Otherwise, this will output null.
 *
 * @return     One if patch has been inserted successfully. Zero if there is
 *             overlap and is not inserted.
 */
int proc_map_try_insert(tai_proc_map_t *map, tai_patch_t *patch, tai_patch_t **existing) {
  int idx;
  int overlap;
  tai_proc_t **item, *proc;
  tai_patch_t **cur, *tmp;

  idx = patch->pid % map->nbuckets;
  *existing = NULL;

  // get proc structure if found
  ksceKernelLockMutex(map->lock, 1, NULL);
  item = &map->buckets[idx];
  while (*item != NULL && (*item)->pid < patch->pid) {
    item = &(*item)->next;
  }
  if (*item != NULL && (*item)->pid == patch->pid) {
    // existing block
    proc = *item;
  } else {
    // new block
    proc = ksceKernelAllocHeapMemory(g_map_pool, sizeof(tai_proc_t));
    proc->pid = patch->pid;
    proc->head = NULL;
    proc->next = *item;
    slab_init(&proc->slab, g_exe_slab_item_size, patch->pid);
    *item = proc;
  }

  // now insert into range if needed
  cur = &proc->head;
  overlap = 0;
  while (*cur != NULL) {
    tmp = *cur;
    if (tmp->addr < patch->addr) {
      if (tmp->addr + tmp->size <= patch->addr) {
        // cur block is completely before our block
        cur = &(*cur)->next;
        continue;
      } else {
        // cur block's end overlaps with our block's start
        overlap = 1;
      }
    } else if (patch->addr < tmp->addr) {
      if (patch->addr + patch->size > tmp->addr) {
        // cur block's start over overlaps with our block's end
        overlap = 1;
      } else {
        // cur block is completely after our block, this is where we insert
      }
    } else { // tmp->addr == patch->addr
      if (patch->size == tmp->size) {
        // completely overlap
        overlap = 1;
        *existing = tmp;
      }
    }
    break;
  }
  if (!overlap) {
    patch->next = *cur;
    patch->slab = &proc->slab;
    *cur = patch;
  }
  ksceKernelUnlockMutex(map->lock, 1);
  return !overlap;
}

/**
 * @brief      Removes every patch associated with a given pid from the map
 *
 *             Returned is a new linked list containing every patch that has
 *             been removed from the proc map. Use the `next` pointer to iterate
 *             this linked list.
 *
 *             Since this invalidates all references for a PID, it should ONLY
 *             be called on the shutdown of a process. In other words, after
 *             calling this, any pointer reference for that process is invalid!
 *
 *             Also note that for optimization, all pointers to `slab` in the
 *             list are considered invalid! Maybe we should null the pointers
 *             out in the future.
 *
 * @param      map   The map
 * @param[in]  pid   The pid to remove
 * @param[out] head  The head of the linked list contained items removed
 *
 * @return     One if any item has been removed.
 */
int proc_map_remove_all_pid(tai_proc_map_t *map, SceUID pid, tai_patch_t **head) {
  int idx;
  tai_proc_t **cur, *tmp;

  idx = pid % map->nbuckets;
  *head = NULL;
  ksceKernelLockMutex(map->lock, 1, NULL);
  cur = &map->buckets[idx];
  while (*cur != NULL && (*cur)->pid < pid) {
    cur = &(*cur)->next;
  }
  if (*cur != NULL && (*cur)->pid == pid) {
    tmp = *cur;
    *cur = tmp->next;
    *head = tmp->head;
    slab_destroy(&tmp->slab);
    ksceKernelFreeHeapMemory(g_map_pool, tmp);
  }
  ksceKernelUnlockMutex(map->lock, 1);
  return *head != NULL;
}

/**
 * @brief      Remove a single patch from the map
 *
 * @param      map    The map
 * @param      patch  The patch to remove
 *
 * @return     One if the patch was removed from the map and zero
 *             otherwise.
 */ 
int proc_map_remove(tai_proc_map_t *map, tai_patch_t *patch) {
  int idx;
  int found;
  tai_proc_t **proc, *next;
  tai_patch_t **cur;

  idx = patch->pid % map->nbuckets;
  found = 0;
  ksceKernelLockMutex(map->lock, 1, NULL);
  proc = &map->buckets[idx];
  while (*proc != NULL && (*proc)->pid < patch->pid) {
    proc = &(*proc)->next;
  }
  if (*proc != NULL && (*proc)->pid == patch->pid) {
    cur = &(*proc)->head;
    while (*cur != NULL && *cur != patch) {
      cur = &(*cur)->next;
    }
    if (*cur != NULL) {
      *cur = patch->next;
      found = 1;
    }
  }
  if (*proc != NULL && (*proc)->head == NULL) { // it's now empty
    patch->slab = NULL; // remove reference
    next = (*proc)->next;
    slab_destroy(&(*proc)->slab);
    ksceKernelFreeHeapMemory(g_map_pool, *proc);
    *proc = next;
  }
  ksceKernelUnlockMutex(map->lock, 1);
  return found;
}
