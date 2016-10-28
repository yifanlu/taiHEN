/* test_api_kernel.c -- kernel plugin interface tests
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include "../taihen.h"
#include "../module.h"
#include "../patches.h"
#include "../proc_map.h"

/** Macro for printing test messages with an identifier */
#ifndef NO_TEST_OUTPUT
#define TEST_MSG(fmt, ...) printf("[%s] " fmt "\n", name, ##__VA_ARGS__)
#else
#define TEST_MSG(fmt, ...)
#endif

/** This mutex will be unlocked whenever a test is done */
static SceUID g_done_lock;

/** This mutex will be unlocked whenever the tests can continue */
static SceUID g_wait_lock;

/** Built in PRNG */
int sceKernelGetRandomNumberForDriver(void *out, size_t len);

/**
 * @brief      Creates a random permutation of integers 0..limit-2
 *
 *             `limit` MUST BE PRIME! `ordering` is an array of size limit-1.
 *
 * @param[in]  rn        Random number
 * @param[in]  limit     The limit (MUST BE PRIME). Technically another
 *                       constraint is limit > 0 but 0 is not prime ;)
 * @param[out] ordering  An array of permutated indexes uniformly distributed
 */
static inline void permute_index(int rn, int limit, int ordering[limit-1]) {
  ordering[0] = (unsigned)rn % (limit-1);
  for (int i = 1; i < limit-1; i++) {
    ordering[i] = (ordering[i-1] + ordering[0] + 1) % limit;
  }
}

/** Number of random hooks */
#define TEST_1_NUM_HOOKS      10

/** References to the hooks */
static tai_hook_ref_t g_hooks[TEST_1_NUM_HOOKS];

/** References to the hooks */
static SceUID g_refs[TEST_1_NUM_HOOKS];

/** Set by each hook */
static int g_passed[TEST_1_NUM_HOOKS];

#define HOOK(x) static int hook ##x (int r0, int r1, int r2, int r3) { \
  const char *name = "hook"; \
  g_passed[x]++; \
  TEST_MSG("called: %d", x); \
  return TAI_CONTINUE(int, g_hooks[x], r0, r1, r2, r3); \
}

HOOK(0) HOOK(1) HOOK(2) HOOK(3) HOOK(4) HOOK(5) HOOK(6) HOOK(7) HOOK(8) HOOK(9)

/** List of function pointers */
static void *hooks[] = {hook0, hook1, hook2, hook3, hook4, hook5, hook6, hook7, hook8, hook9};

/**
 * @brief      Test hooking functions
 *
 *             This will hook an export, an import, and an offset.
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  The flavor of the test
 *
 * @return     Success
 */
int test_scenario_1(const char *name, int flavor) {
  int i, j;
  int ret;
  tai_module_info_t info;
  int ordering[TEST_1_NUM_HOOKS];
  permute_index(flavor, TEST_1_NUM_HOOKS+1, ordering);
  info.size = sizeof(info);
  ret = taiGetModuleInfoForKernel(KERNEL_PID, "SceIofilemgr", &info);
  TEST_MSG("taiGetModuleInfoForKernel: %x", ret);
  if (ret < 0) {
    return ret;
  }
  for (j = 0; j < TEST_1_NUM_HOOKS; j++) {
    i = ordering[j];
    TEST_MSG("adding hook %d", i);
    switch (i % 3) {
      case 0: g_refs[i] = taiHookFunctionExportForKernel(KERNEL_PID, &g_hooks[i], "SceIofilemgr", TAI_ANY_LIBRARY, 0x75192972, hooks[i]); break;
      case 1: g_refs[i] = taiHookFunctionImportForKernel(KERNEL_PID, &g_hooks[i], "SceIofilemgr", 0x7EE45391, 0x38463759, hooks[i]); break;
      case 2: g_refs[i] = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_hooks[i], info.modid, 0, 0x14f1c, 1, hooks[i]); break;
    }
    TEST_MSG("hook %d: %x, %p", i, g_refs[i], g_hooks[i]);
    if (g_refs[i] < 0) {
      return g_refs[i];
    }
    g_passed[i] = 0;
  }
  return 0;
}

/**
 * @brief      Test that hooks are successful
 *
 * @param[in]  name  The name
 *
 * @return     Zero on success, < 0 on error
 */
int test_scenario_1_test_hooks(const char *name) {
  int ret, i;

  ret = sceIoOpenForDriver("ux0:bad", 0, 0);
  for (i = 0; i < TEST_1_NUM_HOOKS; i++) {
    if (g_passed[i] > 0) {
      TEST_MSG("HOOKS PASSED: %d, called: %d", i, g_passed[i]);
    } else {
      TEST_MSG("HOOKS FAILED: %d, called: 0", i);
      return -1;
    }
  }
  return 0;
}

/**
 * @brief      Test freeing hooked functions
 *
 *             This will free a hook for an export, an import, and an offset.
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  The flavor of the test
 *
 * @return     Success
 */
int test_scenario_1_cleanup(const char *name, int flavor) {
  int ret;
  int i, j;
  int ordering[TEST_1_NUM_HOOKS];
  permute_index(flavor / 2, TEST_1_NUM_HOOKS+1, ordering);
  for (j = 0; j < TEST_1_NUM_HOOKS; j++) {
    i = ordering[j];
    TEST_MSG("releasing hook %d", i);
    ret = taiHookReleaseForKernel(g_refs[i], g_hooks[i]);
    TEST_MSG("release %d: %x", i, ret);
    g_passed[i] = 0;
    g_refs[i] = 0;
    g_hooks[i] = 0;
  }
  ret = sceIoOpenForDriver("ux0:bad", 0, 0);
  for (i = 0; i < TEST_1_NUM_HOOKS; i++) {
    if (g_passed[i] == 0) {
      TEST_MSG("RELEASE PASSED: %d, called: 0", i);
    } else {
      TEST_MSG("RELEASE FAILED: %d, called: %d", i, g_passed[i]);
      return -1;
    }
  }
  return 0;
}

/** Number of random injections */
#define TEST_2_NUM_INJECT      12

/** References to the injections */
static SceUID g_inj_refs[TEST_2_NUM_INJECT];

/**
 * @brief      Test injections
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  The flavor of the test
 *
 * @return     Success
 */
int test_scenario_2(const char *name, int flavor) {
  const uint16_t dat = 0x4770;
  int i, j, ret;
  int ordering[TEST_2_NUM_INJECT];
  size_t offset;
  tai_module_info_t info;
  permute_index(flavor, TEST_2_NUM_INJECT+1, ordering);
  info.size = sizeof(info);
  ret = taiGetModuleInfoForKernel(KERNEL_PID, "SceIofilemgr", &info);
  TEST_MSG("taiGetModuleInfoForKernel: %x", ret);
  if (ret < 0) {
    return ret;
  }
  for (j = 0; j < TEST_2_NUM_INJECT; j++) {
    i = ordering[j];
    if (i % 2 == 1) {
      offset = 0x4a4;
    } else {
      offset = 0x1dbe0 + i;
    }
    TEST_MSG("adding injection %d", i);
    g_inj_refs[i] = taiInjectDataForKernel(KERNEL_PID, info.modid, 0, offset, &dat, 2);
    TEST_MSG("offset: %x, ret: %x", offset, g_inj_refs[i]);
    if (g_inj_refs[i] < 0) {
      g_inj_refs[i] = 0;
    }
  }
  return 0;
}

/**
 * @brief      Test freeing injections
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  The flavor of the test
 *
 * @return     Success
 */
int test_scenario_2_cleanup(const char *name, int flavor) {
  int ret;
  int i, j;
  int ordering[TEST_2_NUM_INJECT];
  permute_index(flavor / 2, TEST_2_NUM_INJECT+1, ordering);
  for (j = 0; j < TEST_2_NUM_INJECT; j++) {
    i = ordering[j];
    if (g_inj_refs[i] > 0) {
      TEST_MSG("removing injection %d", i);
      ret = taiInjectReleaseForKernel(g_inj_refs[i]);
      TEST_MSG("release %d: %x", i, ret);
      g_inj_refs[i] = 0;
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
  int ret;
  int test = flavor % 2;

  TEST_MSG("Running test:%d flavor:%d", test, flavor / 2);
  if (test) {
    return test_scenario_1(name, flavor / 2);
  } else {
    return test_scenario_2(name, flavor / 2);
  }
}

/**
 * @brief      Randomly pick between test 1 or test 2
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  Unused
 *
 * @return     Success
 */
int test_scenario_3_cleanup(const char *name, int flavor) {
  int ret;
  int test = flavor % 2;

  TEST_MSG("Running cleanup test:%d flavor:%d", test, flavor / 2);
  if (test) {
    return test_scenario_1_cleanup(name, flavor / 2);
  } else {
    return test_scenario_2_cleanup(name, flavor / 2);
  }
}

/** Number of threads for tests. */
#define TEST_NUM_THREADS 32

/**
 * @brief      Arguments for test thread
 */
struct thread_args {
  int (*test) (const char *, int);
  int (*test_cleanup) (const char *, int);
  const char *prefix;
  int index;
  int flavor;
};

/**
 * @brief      Pthreads start for a test
 *
 * @param      arg   The argument
 *
 * @return     NULL
 */
int start_test(SceSize args, void *argp) {
  struct thread_args *targs = (struct thread_args *)argp;
  int ret;
  char name[256];
  snprintf(name, 256, "%s-thread-%d", targs->prefix, targs->index);
  ret = targs->test(name, targs->flavor);
  if (ret < 0) {
    TEST_MSG("Test failed, releasing all locks.");
    sceKernelUnlockMutexForKernel(g_wait_lock, TEST_NUM_THREADS);
    return ret;
  }
  sceKernelUnlockMutexForKernel(g_done_lock, 1);
  sceKernelLockMutexForKernel(g_wait_lock, 1, NULL);
  ret = targs->test_cleanup(name, targs->flavor);
  if (ret < 0) {
    TEST_MSG("Test cleanup failed");
  }
  return ret;
}

/**
 * @brief      Multi threaded tests
 *
 * @param[in]  type  The type, 1 = test_1, 2 = test_2, 3 = test_3
 *
 * @return     Zero on success, < 0 on error
 */
static int multi_threaded(int type) {
  const char *name = "multi-thread";
  int i;
  int ret;
  SceUID threads[TEST_NUM_THREADS];
  struct thread_args args[TEST_NUM_THREADS];

  g_wait_lock = sceKernelCreateMutexForKernel("wait", 0, 0, NULL);
  g_done_lock = sceKernelCreateMutexForKernel("done", 0, 0, NULL);

  for (i = 0; i < TEST_NUM_THREADS; i++) {
    threads[i] = sceKernelCreateThreadForKernel("test", start_test, 64, 0x1000, 0, 0x10000, 0);
    TEST_MSG("create thread %d: %x", i, threads[i]);
    sceKernelGetRandomNumberForDriver(&args[i].flavor, sizeof(int));
    switch (type) {
      case 1: args[i].test = test_scenario_1; args[i].test_cleanup = test_scenario_1_cleanup; args[i].prefix = "hooks"; break;
      case 2: args[i].test = test_scenario_2; args[i].test_cleanup = test_scenario_2_cleanup; args[i].prefix = "injects"; break;
      case 3: args[i].test = test_scenario_3; args[i].test_cleanup = test_scenario_3_cleanup; args[i].prefix = "mixed"; break;
    }
    args[i].index = i;
  }

  for (i = 0; i < TEST_NUM_THREADS; i++) {
    ret = sceKernelStartThreadForKernel(threads[i], sizeof(args[i]), &args[i]);
    TEST_MSG("started thread %d: %x", i, ret);
  }

  TEST_MSG("wait for threads to hit checkpoint");
  sceKernelLockMutexForKernel(g_done_lock, TEST_NUM_THREADS, NULL);
  TEST_MSG("all threads done, testing hooks");
  TEST_MSG("open: %x", ret);
  if (type & 1) {
    test_scenario_1_test_hooks(name);
  }
  sceKernelUnlockMutexForKernel(g_wait_lock, TEST_NUM_THREADS);

  TEST_MSG("waiting for threads to complete");
  for (i = 0; i < TEST_NUM_THREADS; i++) {
    if (sceKernelWaitThreadEndForKernel(threads[i], &ret, NULL) < 0) {
      TEST_MSG("wait %d timed out", i);
    }
    TEST_MSG("thread %d returned %x", i, ret);
    if (ret < 0) {
      return ret;
    }
    sceKernelDeleteThreadForKernel(threads[i]);
  }

  sceKernelDeleteMutexForKernel(g_wait_lock);
  sceKernelDeleteMutexForKernel(g_done_lock);
  return 0;
}

static int single_threaded(void) {
  const char *name = "single-thread";
  int flavor;
  int ret;

  sceKernelGetRandomNumberForDriver(&flavor, sizeof(int));
  ret = test_scenario_1("st-hook-uniform", flavor);
  if (ret < 0) return ret;
  ret = test_scenario_1_test_hooks("st-hook-uniform");
  if (ret < 0) return ret;
  ret = test_scenario_1_cleanup("st-hook-uniform", flavor);
  if (ret < 0) return ret;
  sceKernelGetRandomNumberForDriver(&flavor, sizeof(int));
  ret = test_scenario_2("st-inject", flavor);
  if (ret < 0) return ret;
  ret = sceIoOpenForDriver(name, 0, 0);
  TEST_MSG("open after inject: %x", ret);
  if ((void *)ret != name) return -1;
  ret = test_scenario_2_cleanup("st-inject", flavor);
  if (ret < 0) return ret;

  return 0;
}

int _start(void) {
  const char *name = "main";
  int ret;
  TEST_MSG("Initializing system");
  ret = proc_map_init();
  TEST_MSG("proc_map_init: %x", ret);
  if (ret < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  ret = patches_init();
  TEST_MSG("patches_init: %x", ret);
  if (ret < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  TEST_MSG("Testing single thread");
  if (single_threaded() < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  TEST_MSG("Testing multiple threads, test 1");
  if (multi_threaded(1) < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  TEST_MSG("Testing multiple threads, test 2");
  if (multi_threaded(2) < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  TEST_MSG("Testing multiple threads, test 3");
  if (multi_threaded(3) < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  TEST_MSG("patches_deinit");
  patches_deinit();
  TEST_MSG("proc_map_deinit");
  proc_map_deinit();
  return 0;
}
