/* plugin.c -- Config and plugin loading
 *
 * Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <taihen/parser.h>
#include "error.h"
#include "plugin.h"
#include "taihen_internal.h"

/** Memory reference to config read buffer */
static SceUID g_config_blk;

/** Buffer for the config data */
static char *g_config = NULL;

/** Mutex for accessing g_config */
static SceUID g_config_lock;

/** Set for delayed load of config */
static int g_delayed_load_config;

/** Set for delayed load of kernel plugins */
static int g_delayed_load_kernel_plugins;

int plugin_init(void) {
  g_config_lock = ksceKernelCreateMutex("tai_config_lock", SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL);
  LOG("ksceKernelCreateMutex(tai_config_lock): 0x%08X", g_config_lock);
  if (g_config_lock < 0) {
    return g_config_lock;
  }
  return TAI_SUCCESS;
}

void plugin_deinit(void) {
  LOG("Cleaning up plugin subsystem.");
  ksceKernelDeleteMutex(g_config_lock);
}

/**
 * @brief      Load tai config file
 *
 *             Frees any existing config, then allocates memory and loads config
 *             to it. First ux0:tai/config.txt will be looked. Followed by
 *             ur0:tai/config.txt
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_BLOCKING if attempted to call during plugin load
 */
int plugin_load_config(void) {
  SceUID fd;
  SceOff len;
  int ret;
  char *config;
  int rd, total;

  if (ksceKernelTryLockMutex(g_config_lock, 1) < 0) {
    return TAI_ERROR_BLOCKING;
  }

  if (g_config) {
    LOG("freeing previous config");
    ksceKernelFreeMemBlock(g_config_blk);
    g_config = NULL;
  }

  LOG("opening config %s", TAIHEN_CONFIG_FILE);
  fd = ksceIoOpen(TAIHEN_CONFIG_FILE, SCE_O_RDONLY, 0);
  if (fd < 0) {
    LOG("failed to open config %s", TAIHEN_CONFIG_FILE);
    LOG("opening recovery config %s", TAIHEN_RECOVERY_CONFIG_FILE);
    fd = ksceIoOpen(TAIHEN_RECOVERY_CONFIG_FILE, SCE_O_RDONLY, 0);
    if (fd < 0) {
      ret = fd;
      goto end;
    }
  }

  len = ksceIoLseek(fd, 0, SCE_SEEK_END);
  if (len < 0) {
    LOG("failed to seek config");
    ksceIoClose(fd);
    ret = TAI_ERROR_SYSTEM;
    goto end;
  }

  ksceIoLseek(fd, 0, SCE_SEEK_SET);

  LOG("allocating %d bytes for config", (len + 0xfff) & ~0xfff);
  g_config_blk = ksceKernelAllocMemBlock("tai_config", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW, (len + 0xfff) & ~0xfff, NULL);
  if (g_config_blk < 0) {
    LOG("failed to allocate memory: %x", g_config_blk);
    ksceIoClose(fd);
    ret = g_config_blk;
    goto end;
  }

  ret = ksceKernelGetMemBlockBase(g_config_blk, (void **)&config);
  if (ret < 0) {
    LOG("failed to get base for %x: %x", g_config_blk, ret);
    ksceIoClose(fd);
    goto end;
  }

  LOG("reading config to memory");
  rd = total = 0;
  while (total < len) {
    rd = ksceIoRead(fd, config+total, len-total);
    if (rd < 0) {
      LOG("failed to read config: rd %x, total %x, len %x", rd, total, len);
      ret = rd;
      break;
    }
    total += rd;
  }

  ksceIoClose(fd);
  if (ret < 0) {
    ksceKernelFreeMemBlock(g_config_blk);
    goto end;
  }

  if ((ret = taihen_config_validate(config)) != 0) {
    LOG("config parsing failed: %x", ret);
    ksceKernelFreeMemBlock(g_config_blk);
    goto end;
  }

  g_config = config;
  ret = TAI_SUCCESS;
end:
  ksceKernelUnlockMutex(g_config_lock, 1);
  return ret;
}

/**
 * @brief      Frees tai config file
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_BLOCKING if attempted to call during plugin load
 */
int plugin_free_config(void) {
  if (ksceKernelTryLockMutex(g_config_lock, 1) < 0) {
    return TAI_ERROR_BLOCKING;
  }
  if (g_config) {
    ksceKernelFreeMemBlock(g_config_blk);
  }
  ksceKernelUnlockMutex(g_config_lock, 1);
  return TAI_SUCCESS;
}

/**
 * @brief      Callback to config parser to load a plugin
 *
 * @param[in]  path   The path to load
 * @param[in]  param  Pointer to the PID to load plugin to.
 */
static void plugin_load(const char *path, void *param) {
  SceUID pid = *(SceUID *)param;
  int ret;
  int result;

  LOG("pid:%x loading module %s", pid, path);
  ret = ksceKernelLoadStartModuleForPid(pid, path, 0, NULL, 0, NULL, &result);
  LOG("load result: %x", ret);
}

/**
 * @brief      Parses the taiHEN config and loads all plugins for a titleid to a
 *             process
 *
 * @param[in]  pid      The pid to load to
 * @param[in]  titleid  The title to read from the config
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_SYSTEM if the config file is invalid
 */
int plugin_load_all(SceUID pid, const char *titleid) {
  int ret;
  g_delayed_load_config = 0;
  g_delayed_load_kernel_plugins = 0;
  ksceKernelLockMutex(g_config_lock, 1, NULL);
  if (g_config) {
    taihen_config_parse(g_config, titleid, plugin_load, &pid);
    ret = TAI_SUCCESS;
  } else {
    LOG("config not loaded");
    ret = TAI_ERROR_SYSTEM;
  }
  ksceKernelUnlockMutex(g_config_lock, 1);
  if (g_delayed_load_config) {
    plugin_load_config();
  }
  if (g_delayed_load_kernel_plugins) {
    plugin_load_all(KERNEL_PID, "KERNEL");
  }
  return ret;
}

/**
 * @brief      (Re)loads the config _after_ `plugin_load_all` completes.
 *
 *             The use case here is if a plugin load changes the config.txt and
 *             needs taiHEN to reload it. This cannot be done normally because
 *             the config.txt is being parsed still, so this schedules it to be
 *             done afterwards.
 *             
 *             This function does nothing if called outside of a start handler.
 *
 * @param[in]  load_kernel  Load all kernel plugins as well.
 *
 * @return     Zero
 */
int plugin_delayed_load_config(int load_kernel) {
  g_delayed_load_config = 1;
  if (load_kernel) {
    g_delayed_load_kernel_plugins = 1;
  }
  return TAI_SUCCESS;
}
