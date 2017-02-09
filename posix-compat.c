/* posix-compat.c -- POSIX functions for libsubstitute to use
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <stdlib.h>
#include <string.h>

/** From `patches.c`. Assumes it is initialized before first `malloc` call! */
extern SceUID g_patch_pool;

/**
 * @brief      Allocates heap memory from default pool
 *
 * @param[in]  size  The size
 *
 * @return     See `malloc()`
 */
void *malloc(size_t size) {
  void *ptr;
  ptr = ksceKernelAllocHeapMemory(g_patch_pool, size + sizeof(size_t));
  if (ptr) {
    *(size_t *)ptr = size;
    ptr = (char *)ptr + sizeof(size_t);
  }
  return ptr;
}

/**
 * @brief      Frees heap memory from default pool
 *
 * @param      ptr   The pointer
 */
void free(void *ptr) {
  ksceKernelFreeHeapMemory(g_patch_pool, (char *)ptr - sizeof(size_t));
}

/**
 * @brief      Reallocates memory to new size
 *
 * @param      ptr   The pointer
 * @param[in]  size  The size
 *
 * @return     See `realloc()`
 */
void *realloc(void *ptr, size_t size) {
  void *dup;
  size_t oldsize;

  dup = malloc(size);
  if (dup) {
    oldsize = *(size_t *)((char *)ptr - sizeof(size_t));
    if (oldsize > size) {
      oldsize = size;
    }
    memcpy(dup, ptr, oldsize);
    free(ptr);
  }
  return dup;
}

/**
 * @brief      Crashes kernel with unrecoverable error
 */
void __attribute__((naked)) abort(void) {
  asm ("bkpt #0");
}
