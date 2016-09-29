/* patches_map.c -- map structure for efficient patch storage
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2/types.h>
#include "taihen_internal.h"

/**
 * @file patches_map.c
 * @brief      A hashmap-linkedlist hybrid structure for storing patches.
 *
 *             The goal of this structure is to provide: 1. Fast lookup by
 *             memory range to answer membership queries. 2. Fast lookup by
 *             associated PID to return a set by PID
 *
 *             To do this, we store the same underlying data in two map
 *             structures. `tai_proc_map_t` is a hashmap ordered by PID. It
 *             allows one to quickly remove a entire set of entries by PID,
 *             which is returned in a linked list. `tai_range_map_t` has a
 *             linked list for each PID sorted by the address of the patch. This
 *             allows an insertion to quickly return an existing patch for a
 *             given address.
 *
 *             The user can use one of the two maps if desired. If both maps are
 *             used, the user is responsible to keeping track of both maps.
 */

/** Size of the heap pool for storing the map in bytes. */
#define MAP_POOL_SIZE 1024

/** Resource pointer for the heap pool */
static SceUID g_map_pool;

/**
 * @brief      Initializes the map system
 *
 *             Must be called on startup.
 *
 * @return     Zero on success or memory allocation error code.
 */
int map_init(void) {
  g_map_pool = sceKernelMemPoolCreate("tai_maps", MAP_POOL_SIZE, NULL);
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
void map_deinit(void) {
  sceKernelMemPoolDestroy(g_map_pool);
  g_map_pool = 0;
}

/**
 * @brief      Allocates a new map
 *
 *             The user determines what kind of map this will be used for. Do
 *             not interchange map types once it's been decided. The user must
 *             call `map_free` to clean up the map when done.
 *
 * @param[in]  nbuckets  The number of buckets for the hash map.
 *
 * @return     Pointer to an allocated map structure on success. Null on
 *             failure.
 */
tai_map_t *map_alloc(int nbuckets) {
  tai_map_t *map;

  map = sceKernelMemPoolAlloc(g_map_pool, sizeof(tai_map_t) + sizeof(tai_patch_t *) * nbuckets);
  if (map == NULL) {
    return NULL;
  }
  map->nbuckets = nbuckets;
  map->lock = sceKernelCreateMutexForKernel("tai_map", SCE_KERNEL_MUTEX_ATTR_TH_FIFO | SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL);
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
void map_free(tai_map_t *map) {
  sceKernelDestroyMutexForKernel(map->lock);
  sceKernelMemPoolFree(g_map_pool, map);
}

/**
 * @brief      Inserts into a proc map
 *
 * @param      map    The proc map
 * @param      patch  The patch to return
 *
 * @return     Always 1 for success
 */
int map_proc_insert(tai_proc_map_t *map, tai_patch_t *patch) {
  int idx;
  tai_patch_t **cur;

  idx = patch->pid % map->nbuckets;
  // we group the patches by NID in sorted order
  sceKernelLockMutexForKernel(map->lock, 1, NULL);
  cur = &map->buckets[i];
  while (*cur != NULL && (*cur)->pid < patch->pid) {
    cur = &(*cur)->proc_next;
  }
  patch->proc_next = *cur;
  *cur = patch;
  patch->free_next = NULL; // clear this pointer
  sceKernelUnlockMutexForKernel(map->lock, 1);

  return 1;
}

/**
 * @brief      Inserts into a range map if no overlap or get patch that
 *             completely overlaps
 *
 *             If there is no overlap with any other element for a given PID,
 *             then insert the patch into the map. If there is overlap, the
 *             function will return zero and not insert the patch. If the
 *             overlap is complete (same address and size), then this will
 *             return a pointer to the overlapping patch also.
 *
 * @param      map       The range map
 * @param[in]  patch     The patch to attempt insert
 * @param[out] existing  If and only if there exists a patch with the same
 *                       address and size, then the function returns zero and
 *                       this pointer will be set to the patch that overlaps.
 *                       Otherwise, this will output null.
 *
 * @return     One if patch has been inserted successfully. Zero if there is
 *             overlap and is not inserted.
 */
int map_range_try_insert(tai_range_map_t *map, tai_patch_t *patch, tai_patch_t **existing) {
  int idx;
  int overlap;
  tai_patch_t **cur, *tmp;

  idx = patch->pid % map->nbuckets;
  *existing = NULL;
  // we group the patches by NID in sorted order
  sceKernelLockMutexForKernel(map->lock, 1, NULL);
  cur = &map->buckets[i];
  overlap = 0;
  while (*cur != NULL) {
    tmp = *cur;
    if (tmp->addr < patch->addr) {
      if (tmp->addr + tmp->len <= patch->addr) {
        // cur block is completely before our block
        cur = &(*cur)->range_next;
        continue;
      } else {
        // cur block's end overlaps with our block's start
        overlap = 1;
      }
    } else if (patch->addr < tmp->addr) {
      if (patch->addr + patch->len > tmp->addr) {
        // cur block's start over overlaps with our block's end
        overlap = 1;
      } else {
        // cur block is completely after our block, this is where we insert
      }
    } else { // tmp->addr == patch->addr
      if (patch->len == tmp->len) {
        // completely overlap
        overlap = 1;
        *existing = tmp;
      }
    }
    break;
  }
  if (!overlap) {
    patch->range_next = *cur;
    *cur = patch;
    patch->free_next = NULL; // clear this pointer
  }
  sceKernelUnlockMutexForKernel(map->lock, 1);
  return !overlap;
}

/**
 * @brief      Removes every patch associated with a given pid from a proc map
 *
 *             Returned is a new linked list containing every patch that has
 *             been removed from the proc map. Use the `free_next` pointer to
 *             iterate this linked list.
 *
 * @param      map      The proc map
 * @param[in]  pid      The pid to remove
 * @param[out] removed  The head of the linked list contained items removed
 *
 * @return     One if any item has been removed.
 */
int map_proc_remove_all_proc(tai_proc_map_t *map, SceUID pid, tai_patch_t **removed) {
  int idx;
  int overlap;
  tai_patch_t **start, **end, *tmp;

  idx = patch->pid % map->nbuckets;
  sceKernelLockMutexForKernel(map->lock, 1, NULL);
  start = &map->buckets[i];
  while (*start != NULL && (*start)->pid < patch->pid) {
    start = &(*start)->proc_next;
  }
  end = start;
  while (*end != NULL && (*end)->pid == patch->pid) {
    (*end)->free_next = (*end)->proc_next; // save a second linked list of things to free
    end = &(*end)->proc_next;
  }
  *removed = *start;
  *start = *end;
  sceKernelUnlockMutexForKernel(map->lock, 1);
  return *removed != NULL;
}

/**
 * @brief      Remove a single patch from the range map
 *
 * @param      map    The range map
 * @param      patch  The patch to remove
 *
 * @return     One if the patch was removed from the map and zero
 *             otherwise.
 */ 
int map_range_remove(tai_range_map_t *map, tai_patch_t *patch) {
  int idx;
  int found;
  tai_patch_t **cur;

  idx = patch->pid % map->nbuckets;
  // we group the patches by NID in sorted order
  sceKernelLockMutexForKernel(map->lock, 1, NULL);
  cur = &map->buckets[i];
  found = 1;
  while (*cur != NULL && *cur != patch) {
    cur = &(*cur)->range_next;
  }
  if (*cur != NULL) {
    *cur = patch->range_next;
  } else {
    // a very serious error... better ignore it.
    found = 0;
  }
  sceKernelUnlockMutexForKernel(map->lock, 1);
  return found;
}
