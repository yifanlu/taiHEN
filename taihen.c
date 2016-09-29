/* taihen.c -- cfw framework for PS Vita
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2/types.h>
#include "taihen_internal.h"

/** @brief      The maximum length for a line in the config file. */
#define MAX_LINE_LEN 256

/**
 * @brief      Reads a line from the config.
 *
 * @param[out] line  The line
 *
 * @return     Actual number of characters read.
 */
static size_t read_line(char line[MAX_LINE_LEN]) {

}

/**
 * @brief      Loads plugins specified by the configuration.
 *
 *             By default, the config is at `ux0:tai/config.txt`. Each line of
 *             the config file is a command. Currently the only commands
 *             supported are
 *
 *             ``` hookuser path [module name] hookkern path ```
 *
 *             The way the `hookuser` command works is that whenever it string
 *             matches module name when a user module is loaded, it will load
 *             the plugin. If the module name is omitted, it will load with
 *             every application launch. The plugin will be unloaded when the
 *             application exits. It is also possible for multiple instances of
 *             the plugin to be loaded if it is hooked into multiple
 *             applications. For `hookkern`, the kernel plugin is loaded at the
 *             start of taiHEN and stays resident until it is manually unloaded
 *             by itself or another plugin. Any line in the config that starts
 *             with `#` will be ignored. This provides a quick way to turn off
 *             plugins. Each line must be at most `MAX_LINE_LEN` characters.
 *
 * @param[in]  path  Path to the config file
 *
 * @return     Zero for success SCE_KERNEL_ERROR code on IO error
 */
static int load_config(const char *path) {

}

/**
 * @brief      Module entry point
 *
 *             This module should be loaded by a kernel exploit. taiHEN expects
 *             the kernel environment to be clean, which means that no outside
 *             hooks and patches which may interfere with taiHEN.
 *
 * @param[in]  argc  Size of arguments (unused)
 * @param[in]  args  The arguments (unused)
 *
 * @return     Success always
 */
int module_start(SceSize argc, const void *args) {

}

/**
 * @brief      Module cleanup
 *
 *             This cleans up the system and removes all hooks and patches. All
 *             handles held by plugins will be invalid after this point! This is
 *             called by the kernel module manager. In usual operation, you
 *             should not unload taiHEN.
 *
 * @param[in]  argc  Size of arguments (unused)
 * @param[in]  args  The arguments (unused)
 *
 * @return     Success always
 */
int module_stop(SceSize argc, const void *args) {

}

/**
 * @brief      Module Exit handler (unused)
 *
 *             This function is currently unused on retail units.
 */
void module_exit(void) {

}
