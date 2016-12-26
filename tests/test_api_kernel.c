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
#include "../error.h"

/** Macro for printing test messages with an identifier */
#ifndef NO_TEST_OUTPUT
#define TEST_MSG(fmt, ...) printf("[%s] " fmt "\n", name, ##__VA_ARGS__)
#else
#define TEST_MSG(fmt, ...)
#endif

/** 3.60 offset */
#define IOFILEMGR_OFFSET_SCEIOOPENFORDRIVER 0x4a4

/** 3.60 offset */
#define IOFILEMGR_OFFSET_SOME_FUNC_CALLED_FROM_SCEIOOPENFORDRIVER 0x14f1c

/** 3.60 offset */
#define IOFILEMGR_OFFSET_JUNK 0x1dbe0

/** This mutex will be unlocked whenever a test is done */
static SceUID g_done_lock;

/** This mutex will be unlocked whenever the tests can continue */
static SceUID g_wait_lock;

/** Built in PRNG */
int ksceKernelGetRandomNumber(void *out, size_t len);

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
      case 2: g_refs[i] = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_hooks[i], info.modid, 0, IOFILEMGR_OFFSET_SOME_FUNC_CALLED_FROM_SCEIOOPENFORDRIVER, 1, hooks[i]); break;
    }
    TEST_MSG("hook %d: %x, %p", i, g_refs[i], g_hooks[i]);
    if (g_refs[i] < 0) {
      if (g_refs[i] == TAI_ERROR_PATCH_EXISTS) {
        g_refs[i] = 0;
        TEST_MSG("existing patch, skipping %d", i);
      } else {
        return g_refs[i];
      }
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

  ret = ksceIoOpen("ux0:bad", 0, 0);
  TEST_MSG("ksceIoOpen: %x", ret);
  for (i = 0; i < TEST_1_NUM_HOOKS; i++) {
    if (!g_refs[i] || g_passed[i] > 0) {
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
    if (g_refs[i] > 0) {
      TEST_MSG("releasing hook %d", i);
      ret = taiHookReleaseForKernel(g_refs[i], g_hooks[i]);
      TEST_MSG("release %d: %x", i, ret);
    } else {
      TEST_MSG("skipping %d", i);
    }
    g_passed[i] = 0;
    g_refs[i] = 0;
    g_hooks[i] = 0;
  }
  ret = ksceIoOpen("ux0:bad", 0, 0);
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

/** thumb instruction for bxlr */
const uint16_t bxlr = 0x4770;

/**
 * @brief      Test injections
 *
 * @param[in]  name    The name of the test
 * @param[in]  flavor  The flavor of the test
 *
 * @return     Success
 */
int test_scenario_2(const char *name, int flavor) {
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
      offset = IOFILEMGR_OFFSET_SCEIOOPENFORDRIVER;
    } else {
      offset = IOFILEMGR_OFFSET_JUNK + i;
    }
    TEST_MSG("adding injection %d", i);
    g_inj_refs[i] = taiInjectDataForKernel(KERNEL_PID, info.modid, 0, offset, &bxlr, 2);
    TEST_MSG("offset: %x, ret: %x", offset, g_inj_refs[i]);
    if (g_inj_refs[i] < 0) {
      if (g_inj_refs[i] == TAI_ERROR_PATCH_EXISTS) {
        g_inj_refs[i] = 0;
        TEST_MSG("existing patch, skipping %d", i);
      } else {
        return g_inj_refs[i];
      }
    }
  }
  return 0;
}

/**
 * @brief      Test injection
 *
 * @param[in]  name  The name
 *
 * @return     Zero on success, < 0 on error
 */
int test_scenario_2_test_inject(const char *name) {
  int ret;
  ret = ksceIoOpen(name, 0, 0);
  TEST_MSG("open after inject: %x", ret);
  if (ret != (int)name) return -1;
  TEST_MSG("INJECT PASS");
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
    } else {
      TEST_MSG("skipping %d", i);
    }
  }
  return 0;
}

/** Number of threads for tests. */
#define TEST_NUM_THREADS (TEST_1_NUM_HOOKS > TEST_2_NUM_INJECT ? TEST_1_NUM_HOOKS : TEST_2_NUM_INJECT)

/** Counter for done */
static int g_done_count = 0;

/**
 * @brief      Arguments for test thread
 */
struct thread_args {
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
  int i;
  int flavor;
  int skip;
  tai_module_info_t info;

  snprintf(name, 256, "%s-thread-%d", targs->prefix, targs->index);

  i = targs->index;
  flavor = targs->flavor;
  ret = 0;
  skip = 0;

  TEST_MSG("starting test phase");
  if (flavor % 2) {
    if (i >= TEST_1_NUM_HOOKS) {
      TEST_MSG("no space, exiting");
      skip = 1;
      goto wait;
    }
    ret = g_refs[i] = taiHookFunctionExportForKernel(KERNEL_PID, &g_hooks[i], "SceIofilemgr", TAI_ANY_LIBRARY, 0x75192972, hooks[i]);
    if (ret == TAI_ERROR_PATCH_EXISTS) {
      TEST_MSG("patch exists");
      ret = g_refs[i] = 0;
      g_hooks[i] = 0;
    } else if (ret < 0) {
      goto wait;
    }
  } else {
    if (i >= TEST_2_NUM_INJECT) {
      TEST_MSG("no space, exiting");
      skip = 1;
      goto wait;
    }
    info.size = sizeof(info);
    ret = taiGetModuleInfoForKernel(KERNEL_PID, "SceIofilemgr", &info);
    if (ret >= 0) {
      ret = g_inj_refs[i] = taiInjectDataForKernel(KERNEL_PID, info.modid, 0, IOFILEMGR_OFFSET_SCEIOOPENFORDRIVER, &bxlr, 2);
      if (ret == TAI_ERROR_PATCH_EXISTS) {
        TEST_MSG("patch exists");
        ret = g_inj_refs[i] = 0;
      } else if (ret < 0) {
        goto wait;
      }
    }
  }
  if (ret < 0) {
    TEST_MSG("TEST FAILED: %x", ret);
  }
wait:
  ksceKernelLockMutex(g_done_lock, 1, NULL);
  g_done_count++;
  ksceKernelUnlockMutex(g_done_lock, 1);
  TEST_MSG("test start phase complete, waiting for others");
  ksceKernelLockMutex(g_wait_lock, 1, NULL);
  ksceKernelUnlockMutex(g_wait_lock, 1);
  TEST_MSG("starting cleanup phase");
  if (ret >= 0 && !skip) {
    if (flavor % 2) {
      if (g_refs[i]) {
        ret = taiHookReleaseForKernel(g_refs[i], g_hooks[i]);
      }
    } else {
      if (g_inj_refs[i]) {
        ret = taiInjectReleaseForKernel(g_inj_refs[i]);
      }
    }
    if (ret < 0) {
      TEST_MSG("TEST CLEANUP FAILED: %x", ret);
    }
  }
  return ret;
}

/**
 * @brief      Multi threaded tests
 *
 * @param[in]  type  The type, 0 = test_1, 1 = test_2
 *
 * @return     Zero on success, < 0 on error
 */
static int multi_threaded(int type) {
  const char *name = "multi-thread";
  int i;
  int ret;
  SceUID threads[TEST_NUM_THREADS];
  struct thread_args args[TEST_NUM_THREADS];

  g_wait_lock = ksceKernelCreateMutex("wait", 0, 0, NULL);
  g_done_lock = ksceKernelCreateMutex("done", 0, 0, NULL);

  for (i = 0; i < TEST_NUM_THREADS; i++) {
    threads[i] = ksceKernelCreateThread("test", start_test, 64, 0x2000, 0, 0x10000, 0);
    TEST_MSG("create thread %d: %x", i, threads[i]);
    ksceKernelGetRandomNumber(&args[i].flavor, sizeof(int));
    args[i].prefix = type ? "hook" : "inject";
    args[i].index = i;
    args[i].flavor = (args[i].flavor << 1) | type;
  }

  g_done_count = 0;
  ksceKernelLockMutex(g_wait_lock, 1, NULL);
  for (i = 0; i < TEST_NUM_THREADS; i++) {
    ret = ksceKernelStartThread(threads[i], sizeof(args[i]), &args[i]);
    TEST_MSG("started thread %d: %x", i, ret);
  }

  TEST_MSG("wait for threads to hit checkpoint");
  int done, last = 0;
  while (1) {
    ksceKernelLockMutex(g_done_lock, 1, NULL);
    done = g_done_count;
    ksceKernelUnlockMutex(g_done_lock, 1);
    if (done != last) {
      TEST_MSG("done: %d", done);
      last = done;
    }
    if (done == TEST_NUM_THREADS) {
      break;
    }
  }
  TEST_MSG("all threads done, testing hooks");
  if (type & 1) {
    ret = test_scenario_1_test_hooks(name);
  } else {
    ret = test_scenario_2_test_inject(name);
  }
  TEST_MSG("starting cleanup phase");
  ksceKernelUnlockMutex(g_wait_lock, 1);

  TEST_MSG("waiting for threads to complete");
  for (i = 0; i < TEST_NUM_THREADS; i++) {
    if (ksceKernelWaitThreadEnd(threads[i], &ret, NULL) < 0) {
      TEST_MSG("wait %d timed out", i);
    }
    TEST_MSG("thread %d returned %x", i, ret);
    ksceKernelDeleteThread(threads[i]);
  }

  ksceKernelDeleteMutex(g_wait_lock);
  ksceKernelDeleteMutex(g_done_lock);
  return ret;
}

static int single_threaded(void) {
  const char *name = "single-thread";
  int flavor;
  int ret;

  ksceKernelGetRandomNumber(&flavor, sizeof(int));
  ret = test_scenario_1("st-hook-uniform", flavor);
  if (ret < 0) return ret;
  ret = test_scenario_1_test_hooks("st-hook-uniform");
  if (ret < 0) return ret;
  ret = test_scenario_1_cleanup("st-hook-uniform", flavor);
  if (ret < 0) return ret;
  ksceKernelGetRandomNumber(&flavor, sizeof(int));
  ret = test_scenario_2("st-inject", flavor);
  if (ret < 0) return ret;
  ret = test_scenario_2_test_inject("st-inject");
  if (ret < 0) return ret;
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
  if (multi_threaded(0) < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  TEST_MSG("Testing multiple threads, test 2");
  if (multi_threaded(1) < 0) {
    TEST_MSG("FAILED");
    return 0;
  }
  TEST_MSG("patches_deinit");
  patches_deinit();
  TEST_MSG("proc_map_deinit");
  proc_map_deinit();
  return 0;
}
