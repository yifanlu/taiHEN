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
#include <taihen/parser.h>
#include "error.h"
#include "plugin.h"
#include "taihen_internal.h"

/** Memory reference to config read buffer */
static SceUID g_config_blk;

/** Buffer for the config data */
char *g_config = NULL;

/**
 * @brief      Load tai config file
 *
 *             Frees any existing config, then allocates memory and loads config
 *             to it. First ux0:tai/config.txt will be looked. Followed by
 *             ur0:tai/config.txt
 *
 * @return     Zero on success, < 0 on error
 */
int plugin_load_config(void) {
  SceUID fd;
  SceOff len;
  int ret;
  char *config;
  int rd, total;

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
      return fd;
    }
  }

  len = ksceIoLseek(fd, 0, SCE_SEEK_END);
  if (len < 0) {
    LOG("failed to seek config");
    ksceIoClose(fd);
    return TAI_ERROR_SYSTEM;
  }

  ksceIoLseek(fd, 0, SCE_SEEK_SET);

  LOG("allocating %d bytes for config", (len + 0xfff) & ~0xfff);
  g_config_blk = ksceKernelAllocMemBlock("tai_config", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW, (len + 0xfff) & ~0xfff, NULL);
  if (g_config_blk < 0) {
    LOG("failed to allocate memory: %x", g_config_blk);
    ksceIoClose(fd);
    return g_config_blk;
  }

  ret = ksceKernelGetMemBlockBase(g_config_blk, (void **)&config);
  if (ret < 0) {
    LOG("failed to get base for %x: %x", g_config_blk, ret);
    ksceIoClose(fd);
    return ret;
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
    return ret;
  }

  if ((ret = taihen_config_validate(config)) != 0) {
    LOG("config parsing failed: %x", ret);
    ksceKernelFreeMemBlock(g_config_blk);
    return ret;
  }

  g_config = config;
  return TAI_SUCCESS;
}

/**
 * @brief      Frees tai config file
 *
 * @return     Zero on success
 */
int plugin_free_config(void) {
  if (g_config) {
    ksceKernelFreeMemBlock(g_config_blk);
  }
  return 0;
}

/**
 * @brief      Callback to config parser to load a plugin
 *
 *             If no config is loaded, will return without doing anything.
 *
 * @param[in]  path   The path to load
 * @param[in]  param  The parameters
 */
static void plugin_load(const char *path, void *param) {
  SceUID pid = *(SceUID *)param;
  int ret;
  int result;

  if (!g_config) {
    LOG("no config loaded! skipping plugin load");
    return;
  }

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
  if (g_config) {
    taihen_config_parse(g_config, titleid, plugin_load, &pid);
    return TAI_SUCCESS;
  } else {
    LOG("config not loaded");
    return TAI_ERROR_SYSTEM;
  }
}
