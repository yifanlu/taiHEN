/* test_patches.c -- unit tests for patches.c
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

#include "../taihen.h"
#include "../taihen_internal.h"
#include "../patches.h"

/** Macro for printing test messages with an identifier */
#ifndef NO_TEST_OUTPUT
#define TEST_MSG(fmt, ...) printf("[%s] " fmt "\n", name, ##__VA_ARGS__)
#else
#define TEST_MSG(fmt, ...)
#endif

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

/** Number of random hooks */
#define TEST_1_NUM_HOOKS      30

/**
 * @brief      Test random hooks
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  The flavor of the test
 *
 * @return     Success
 */
int test_scenario_1(const char *name, int flavor) {
  tai_hook_ref_t hooks[TEST_1_NUM_HOOKS];
  SceUID uids[TEST_1_NUM_HOOKS];
  int start[TEST_1_NUM_HOOKS];
  int ret;

  permute_index(TEST_1_NUM_HOOKS+1, start);

  for (int i = 0; i < TEST_1_NUM_HOOKS; i++) {
    uintptr_t addr;

    if (flavor == 1) {
      addr = (start[i] % 12) * 4;
    } else {
      addr = start[i] * 16;
    }
    TEST_MSG("Attempting to add hook at addr:%lx", addr);
    if ((uids[i] = tai_hook_func_abs(&hooks[i], 0, (void *)addr, NULL)) < 0) {
      TEST_MSG("Failed to hook addr:%lx", addr);
      hooks[i] = 0;
      uids[i] = 0;
    } else {
      TEST_MSG("Successfully hooked addr:%lx", addr);
    }
  }
  TEST_MSG("Cleanup");
  for (int i = 0; i < TEST_1_NUM_HOOKS; i++) {
    if (hooks[i] != 0) {
      ret = tai_hook_release(uids[i], hooks[i]);
      assert(ret == 0);
    }
  }
  return 0;
}


/** Number of random injections */
#define TEST_2_NUM_INJECT      30

/**
 * @brief      Test random injections
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  The flavor of the test
 *
 * @return     Success
 */
int test_scenario_2(const char *name, int flavor) {
  SceUID uid[TEST_2_NUM_INJECT];
  int start[TEST_2_NUM_INJECT];
  int off[TEST_2_NUM_INJECT];
  int sz[TEST_2_NUM_INJECT];
  int ret;

  permute_index(TEST_2_NUM_INJECT+1, start);
  permute_index(TEST_2_NUM_INJECT+1, off);
  permute_index(TEST_2_NUM_INJECT+1, sz);

  for (int i = 0; i < TEST_2_NUM_INJECT; i++) {
    uintptr_t addr;
    size_t size;

    addr = start[i] * 0x10 + off[i] * 0x10;
    size = sz[i] * 0x10;
    TEST_MSG("Attempting to add injection at addr:%lx, size:%zx", addr, size);
    if ((uid[i] = tai_inject_abs(0, (void *)addr, NULL, size)) < 0) {
      TEST_MSG("Failed to inject addr:%lx, size:%zx", addr, size);
      uid[i] = 0;
    } else {
      TEST_MSG("Successfully injected addr:%lx", addr);
    }
  }
  TEST_MSG("Cleanup");
  for (int i = 0; i < TEST_2_NUM_INJECT; i++) {
    if (uid[i] != 0) {
      ret = tai_inject_release(uid[i]);
      assert(ret == 0);
    }
  }
  return 0;
}

/**
 * @brief      Randomly pick between test 1 or test 2
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  Unused
 *
 * @return     Success
 */
int test_scenario_3(const char *name, int flavor) {
  int test = rand() % 2;
  flavor = rand() % 2;

  TEST_MSG("Running test:%d flavor:%d", test, flavor);
  if (test) {
    return test_scenario_1(name, flavor);
  } else {
    return test_scenario_2(name, flavor);
  }
}

/**
 * @brief      Arguments for test thread
 */
struct thread_args {
  int (*test) (const char *, int);
  const char *prefix;
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
  snprintf(name, 256, "%s-thread-%d", targs->prefix, targs->index);
  targs->test(name, 0);
  return NULL;
}

/** Number of threads for tests. */
#define TEST_NUM_THREADS 32

int main(int argc, const char *argv[]) {
  const char *name = "INIT";
  pthread_t threads[TEST_NUM_THREADS];
  struct thread_args args[TEST_NUM_THREADS];
  
  int seed = 0;

  if (argc > 1) {
    seed = atoi(argv[1]);
    TEST_MSG("Seeding PRNG: %d", seed);
  }
  srand(seed);

  TEST_MSG("Setup patches");
  patches_init();

  TEST_MSG("Phase 1: Single threaded");
  test_scenario_1("hooks_test_1", 0);
  test_scenario_1("hooks_test_2", 1);
  test_scenario_2("injection_test", 0);

  TEST_MSG("Phase 2: Multi threaded");
  TEST_MSG("scenario 1");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    args[i].test = test_scenario_1;
    args[i].index = i;
    args[i].prefix = "hooks";
    pthread_create(&threads[i], NULL, start_test, &args[i]);
  }
  TEST_MSG("cleanup");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  TEST_MSG("scenario 2");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    args[i].test = test_scenario_2;
    args[i].index = i;
    args[i].prefix = "injections";
    pthread_create(&threads[i], NULL, start_test, &args[i]);
  }
  TEST_MSG("cleanup");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  TEST_MSG("scenario 3");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    args[i].test = test_scenario_3;
    args[i].index = i;
    args[i].prefix = "mixed";
    pthread_create(&threads[i], NULL, start_test, &args[i]);
  }
  TEST_MSG("cleanup");
  for (int i = 0; i < TEST_NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }

  TEST_MSG("Cleanup patches");
  patches_deinit();
  return 0;
}
