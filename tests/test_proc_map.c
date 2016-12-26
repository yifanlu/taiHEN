/* test_proc_map.c -- unit tests for proc_map.c
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#include <psp2kern/kernel/threadmgr.h>
#include "../taihen.h"
#include "../taihen_internal.h"
#include "../proc_map.h"

/** Set to 1 to print the status of the map after each operation */
#define VERBOSE 0

/** Macro for printing test messages with an identifier */
#ifndef NO_TEST_OUTPUT
#define TEST_MSG(fmt, ...) printf("[%s] " fmt "\n", name, ##__VA_ARGS__)
#else
#define TEST_MSG(fmt, ...)
#endif

/**
 * @brief      Helper function that allocates a patch
 * 
 * Should be freed with `free()`
 *
 * @param[in]  pid   The pid
 * @param[in]  addr  The address
 * @param[in]  size  The size
 *
 * @return     { description_of_the_return_value }
 */
tai_patch_t *create_patch(SceUID pid, uintptr_t addr, size_t size) {
  tai_patch_t *patch = malloc(sizeof(tai_patch_t));
  patch->pid = pid;
  patch->addr = addr;
  patch->size = size;
  patch->next = NULL;
  patch->type = HOOKS;
  return patch;
}

/**
 * @brief      Creates a random permutation of integers 0..limit-2
 *
 *             `limit` MUST BE PRIME! `ordering` is an array of size limit-1.
 *
 * @param[in]  limit     The limit (MUST BE PRIME). Technically another 
 *                       constraint is limit > 0 but 0 is not prime ;)
 * @param[out] ordering  An array of permutated indexes uniformly distributed
 */
static inline void permute_index(int limit, int ordering[limit-1]) {
  ordering[0] = rand() % (limit-1);
  for (int i = 1; i < limit-1; i++) {
    ordering[i] = (ordering[i-1] + ordering[0] + 1) % limit;
  }
}

/**
 * @brief      Print out the current proc map
 *
 * @param      map   The map
 * @param[in]  lock  If 1, then lock the map before dumping
 */
void proc_map_dump(const char *name, tai_proc_map_t *map, int lock) {
  tai_proc_t *proc;
  tai_patch_t *patch;

  TEST_MSG("Dumping map...");
  if (lock) ksceKernelLockMutex(map->lock, 1, NULL);
  for (int i = 0; i < map->nbuckets; i++) {
    for (proc = map->buckets[i]; proc != NULL; proc = proc->next) {
      TEST_MSG("Proc Item: pid = %d", proc->pid);
      for (patch = proc->head; patch != NULL; patch = patch->next) {
        TEST_MSG("    Patch: pid = %d, addr = %lx, size = %zx", patch->pid, patch->addr, patch->size);
      }
    }
  }
  TEST_MSG("Finished dumping map.");
  if (lock) ksceKernelUnlockMutex(map->lock, 1);
}

/** Number of blocks to insert. Must be prime. */
#define TEST_1_NUM_BLOCKS     6

/**
 * @brief      Scenario 1
 * 
 * This test basically tries to insert 5 non-overlapping regions for a PID and 
 * then remove all items for a PID. It is expected that the test is run from 
 * multiple threads for best coverage.
 *
 * @param[in]  name  The name
 * @param      map   The map
 * @param[in]  pid   The pid
 *
 * @return     Success. Errors will halt the test.
 */
int test_scenario_1(const char *name, tai_proc_map_t *map, SceUID pid) {
  tai_patch_t *possible, *actual;
  int ordering[TEST_1_NUM_BLOCKS];
  int ret;

  permute_index(TEST_1_NUM_BLOCKS+1, ordering);
  for (int i = 0; i < TEST_1_NUM_BLOCKS; i++) {
    possible = create_patch(pid, ordering[i] * 0x100, 0x100);
    TEST_MSG("Inserting for %d addr:%lx, size:%zx", pid, possible->addr, possible->size);
    if (proc_map_try_insert(map, possible, &actual) != 1) {
      assert(actual);
      TEST_MSG("Already exist:%lx, size:%zx", actual->addr, actual->size);
      assert(actual->pid == possible->pid);
      assert(actual->addr == possible->addr);
      assert(actual->size == possible->size);
      free(possible);
    }
    if (VERBOSE) proc_map_dump(name, map, 1);
  }
  TEST_MSG("Remove all for pid %d", pid);
  ret = proc_map_remove_all_pid(map, pid, &actual);
  TEST_MSG("Result: %d", ret);
  if (VERBOSE) proc_map_dump(name, map, 1);
  if (ret) { // only ONE thread should return 1
    tai_patch_t *next;
    uintptr_t last_addr = 0;
    while (actual != NULL) {
      TEST_MSG("Removed block: addr:%lx, size:%zx", actual->addr, actual->size);
      assert(last_addr <= actual->addr);
      assert(actual->size == 0x100);
      assert(actual->pid == pid);
      next = actual->next;
      free(actual);
      actual = next;
    }
  }
  return 0;
}

/** Number of deterministic blocks in test. */
#define TEST_2_NUM_FIXED      2

/** Number of blocks with random ordering in test. Must be prime. */
#define TEST_2_NUM_SCRAMBLE   6

/**
 * @brief      Scenario 2
 *
 *             This test places some fixed blocks and then randomizes the order
 *             of the remaining blocks. It then tries to add each one and then
 *             removes each one.
 *
 * @param[in]  name  The name of the test
 * @param      map   The map
 * @param[in]  pid   The pid
 *
 * @return     Success
 */
int test_scenario_2(const char *name, tai_proc_map_t *map, SceUID pid) {
  tai_patch_t *fixed[TEST_2_NUM_FIXED];
  tai_patch_t *scramble[TEST_2_NUM_SCRAMBLE];
  tai_patch_t *current;
  tai_patch_t *actual;
  int ordering[TEST_2_NUM_SCRAMBLE];
  int success;

  fixed[0] = create_patch(pid, 0x100, 0x50); // block 1
  fixed[1] = create_patch(pid, 0x200, 0x50); // block 2
  scramble[0] = create_patch(pid, 0x50, 0x20); // no overlap before
  scramble[1] = create_patch(pid, 0xf0, 0x20); // overlap tail <-> head
  scramble[2] = create_patch(pid, 0x120, 0x20); // complete overlap
  scramble[3] = create_patch(pid, 0x140, 0x20); // overlap head <-> tail
  scramble[4] = create_patch(pid, 0x90, 0x200); // overlap two blocks
  scramble[5] = create_patch(pid, 0x300, 0x100); // at the end
  permute_index(TEST_2_NUM_SCRAMBLE+1, ordering);
  for (int i = 0; i < TEST_2_NUM_FIXED; i++) {
    TEST_MSG("Adding fixed block %d: addr:%lx, size:%zx", i, fixed[i]->addr, fixed[i]->size);
    success = proc_map_try_insert(map, fixed[i], &actual);
    if (!success) {
      TEST_MSG("Fixed block %d already exists.", i);
      free(fixed[i]);
      fixed[i] = NULL;
    }
    if (VERBOSE) proc_map_dump(name, map, 1);
  }
  for (int i = 0; i < TEST_2_NUM_SCRAMBLE; i++) {
    current = scramble[ordering[i]];
    TEST_MSG("Adding block %d: addr:%lx, size:%zx", i, current->addr, current->size);
    if (proc_map_try_insert(map, current, &actual) != 1) {
      assert(!actual || actual->pid == current->pid);
      TEST_MSG("Block %d failed to insert.", i);
      free(current);
      scramble[ordering[i]] = NULL;
    } else {
      TEST_MSG("Block %d inserted successfully.", i);
    }
    if (VERBOSE) proc_map_dump(name, map, 1);
  }
  for (int i = 0; i < TEST_2_NUM_SCRAMBLE; i++) {
    current = scramble[ordering[i]];
    if (current) {
      TEST_MSG("Removing block %d", i);
      success = proc_map_remove(map, current);
      assert(success);
      free(current);
      scramble[ordering[i]] = NULL;
      if (VERBOSE) proc_map_dump(name, map, 1);
    }
  }
  for (int i = 0; i < TEST_2_NUM_FIXED; i++) {
    if (fixed[i]) {
      TEST_MSG("Removing fixed block %d", i);
      success = proc_map_remove(map, fixed[i]);
      assert(success);
      free(fixed[i]);
      fixed[i] = NULL;
      if (VERBOSE) proc_map_dump(name, map, 1);
    }
  }
  return 0;
}

/**
 * @brief      Arguments for test thread
 */
struct thread_args {
  int (*test) (const char *, tai_proc_map_t *, SceUID);
  tai_proc_map_t *map;
  SceUID pid;
  int index;
};

/**
 * @brief      Pthreads start for a test
 *
 * @param      arg   The argument
 *
 * @return     NULL
 */
void *start_test(void *arg) {
  struct thread_args *targs = (struct thread_args *)arg;
  char name[256];
  snprintf(name, 256, "thread-%d", targs->index);
  targs->test(name, targs->map, targs->pid);
  return NULL;
}

/** Number of buckets in map for tests. */
#define TEST_NUM_BUCKETS 4

/** Number of threads for tests. */
#define TEST_NUM_THREADS 32

int main(int argc, const char *argv[]) {
  const char *name = "INIT";
  tai_proc_map_t *map;
  pthread_t threads[TEST_NUM_THREADS];
  struct thread_args args[TEST_NUM_THREADS];
  
  int seed = 0;

  if (argc > 1) {
    seed = atoi(argv[1]);
    TEST_MSG("Seeding PRNG: %d", seed);
  }
  srand(seed);

  TEST_MSG("Setup maps");
  proc_map_init();
  map = proc_map_alloc(TEST_NUM_BUCKETS);

  TEST_MSG("Phase 1: Single threaded");
  test_scenario_1("single_thread", map, 0);
  proc_map_dump("single_thread", map, 1);
  test_scenario_2("single_thread", map, 0);
  proc_map_dump("single_thread", map, 1);

  TEST_MSG("Phase 2: Multi threaded");
  TEST_MSG("scenario 1");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    args[i].test = test_scenario_1;
    args[i].map = map;
    args[i].pid = i / 4;
    args[i].index = i;
    pthread_create(&threads[i], NULL, start_test, &args[i]);
  }
  TEST_MSG("cleanup");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  proc_map_dump("multi-threads-1", map, 1);
  TEST_MSG("scenario 2");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    args[i].test = test_scenario_2;
    args[i].map = map;
    args[i].pid = i / 4;
    args[i].index = i;
    pthread_create(&threads[i], NULL, start_test, &args[i]);
  }
  TEST_MSG("cleanup");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  proc_map_dump("multi-threads-2", map, 1);

  TEST_MSG("Cleanup maps");
  proc_map_free(map);
  proc_map_deinit();
  return 0;
}
