Usage
================================================================================

Quick Start
--------------------------------------------------------------------------------
Here are a couple of examples that demonstrate how to use the taiHEN APIs.

### Do something on startup

Configure the following user plugin to load on an application named "AppName"
with the title id "ABCD01234".

```c
// handle to our hook
static tai_hook_ref_t app_start_ref;
// our hook for app entry
int hook_app_start(SceSize argc, const void *args) {
  printf("hello world!\n");
  return TAI_CONTINUE(int, app_start_ref, argc, args);
}
// our own plugin entry
int module_start(SceSize argc, const void *args) {
  taiHookFunctionExport(&app_start_ref,  // Output a reference
                        "AppName",       // Name of module being hooked
                        TAI_ANY_LIBRARY, // If there's multiple libs exporting this
                        0x935CD196,      // Special NID specifying module_start
                        hook_app_start); // Name of the hook function
  return SCE_KERNEL_START_SUCCESS;
}
```

We can build this as `myplugin.suprx` and add it to `ux0:tai/config.txt` under
the section `*ABCD01234` and it will be loaded when `ABCD01234` is started and
insert the hook.

### Logging Filesystem

The following example will log all file opens from applications. Compile it as
`kernellog.skprx` and add to `*KERNEL` section in `ux0:tai/config.txt`.

```c
// handle to our hook
static tai_hook_ref_t open_ref;
// this function is in kernel space
SceUID hook_user_open(const char *path, int flags, SceMode mode, void *args) {
  char k_path[256];
  SceUID fd;
  fd = TAI_CONTINUE(SceUID, open_ref, path, flags, mode, args);
  // we need to copy the user pointer to kernel space
  ksceKernelStrncpyUserToKernel(k_path, (uintptr_t)path, 256);
  // do some logging
  printf("opening: %s, res: %x\n", k_path, fd);
  return fd;
}
// plugin entry
int module_start(SceSize argc, const void *args) {
  taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
                                 &open_ref,       // Output a reference
                                 "SceIofilemgr",  // Name of module being hooked
                                 TAI_ANY_LIBRARY, // If there's multiple libs exporting this
                                 0xCC67B6FD,      // NID specifying sceIoOpen
                                 hook_user_open); // Name of the hook function
  return SCE_KERNEL_START_SUCCESS;
}
```

### Chain of hooks

Consider one kernel plugin with the code above. Now consider a second kernel
plugin as follows.

```c
// handle to our hook
static tai_hook_ref_t another_open_ref;
// this function is in kernel space
SceUID hook_user_open_differently(const char *path, int flags, SceMode mode, void *args) {
  char k_path[256];
  SceUID fd;
  fd = TAI_CONTINUE(SceUID, another_open_ref, path, flags, mode, args);
  // we need to copy the user pointer to kernel space
  ksceKernelStrncpyUserToKernel(k_path, (uintptr_t)path, 256);
  // filter out certain paths
  if (strcmp(k_path, "ux0:hidden_file.bin") == 0 && fd >= 0) {
    sceIoClose(fd); // close the handle
    fd = SCE_KERNEL_ERROR_NOENT;
  }
  return fd;
}
// another plugin entry
int module_start(SceSize argc, const void *args) {
  taiHookFunctionExportForKernel(KERNEL_PID,                  // Kernel process
                                 &another_open_ref,           // Output a reference
                                 "SceIofilemgr",              // Name of module being hooked
                                 TAI_ANY_LIBRARY,             // If there's multiple libs exporting this
                                 0xCC67B6FD,                  // NID specifying sceIoOpen
                                 hook_user_open_differently); // Name of the hook function
  return SCE_KERNEL_START_SUCCESS;
}
```

Now we have both filesystem filtering _and_ logging.

### Enabling dynarec

This plugin will be loaded in kernel and changes the return value of a function
that does a check to enable dynarec.

```c
// handle to our hook
static tai_hook_ref_t some_sysroot_check_hook;
// patch function
static int some_sysroot_check_patched(void) {
  // It is important that we always call `TAI_CONTINUE` regardless if we need 
  // the return value or not. This ensures other hooks in the chain can run!
  TAI_CONTINUE(int, some_sysroot_check_hook);
  return 1;
}
// plugin entry
int module_start(SceSize argc, const void *args) {
  taiHookFunctionExportForKernel(KERNEL_PID,                  // Kernel process
                                 &some_sysroot_check_hook,    // Output a reference
                                 "SceSysmem",                 // Name of module being hooked
                                 0x3691DA45,                  // NID specifying SceSysrootForKernel
                                 0xF8769E86,                  // NID of the export function we patch
                                 some_sysroot_check_patched); // Name of the hook function
  return SCE_KERNEL_START_SUCCESS;
}
```

### Local file logging

The above examples are all global hooks: every call regardless of origin will be
hooked. You can also insert local hooks: a library import from a module. In this
example, we have a user plugin loaded with "AppName" that only logs `sceIoOpen`
calls from that application.

```c
// handle to our hook
static tai_hook_ref_t local_open_hook;
// this function is in user space now
SceUID hook_local_open(const char *path, int flags, SceMode mode) {
  SceUID fd;
  fd = TAI_CONTINUE(SceUID, local_open_hook, path, flags, mode);
  printf("open in AppName: %s, ret: %x", path, fd);
  return fd;
}
// our own plugin entry
int module_start(SceSize argc, const void *args) {
  taiHookFunctionImport(&local_open_hook,  // Output a reference
                        "AppName",         // Name of module being hooked
                        0xCAE9ACE6,        // NID specifying SceLibKernel, a wrapper library
                        0x6C60AC61,        // NID specifying sceIoOpen
                        hook_local_open);  // Name of the hook function
  return SCE_KERNEL_START_SUCCESS;
}
```

Advanced Usage
--------------------------------------------------------------------------------
Below are some common tasks and paradigms that might be of interest to people
writing advanced hooks.

### Hooking shared libraries

Currently taiHEN does not support hooking the exports of shared libraries (or
the imports from shared libraries). Shared libraries are ones loaded in the
`0xE0000000` address range and are mainly in modules that most applications
import from (example being `SceLibKernel` and `SceGxm`). You can, however, hook
imports of shared libraries as usual. So, if multiple non-shared modules import
a function of interest, you must hook all of them (if desired).

### Hooking weak imports

Weak imports are imports of modules not loaded at application startup and are
loaded by `sceSysmoduleLoadModule` (in `SceSysmodule`) or
`sceKernelLoadStartModule` (in `SceLibKernel`) or some other function. They
typically are loaded on-demand and unloaded when no longer needed to save
memory. That means that your hooks must be created after the module is loaded
and removed before the module is unloaded. To do this, you have to first hook
the module load and unload imports and in those hooks, you create/remove the
desired hook. In this example, we wish to hook `sceScreenShotDisable` which is
loaded by the game from `sceSysmoduleLoadModule`.

```c
// handle to our hooks
static tai_hook_ref_t load_hook;
static tai_hook_ref_t unload_hook;
static tai_hook_ref_t ss_disable_hook;
static SceUID ss_disable_uid;
// hook to never disable screenshots
int hook_ss_disable(void) {
  int ret;
  TAI_CONTINUE(int, ss_disable_hook); // so others get a chance to hook
  ret = sceScreenShotEnable(); // we always re-enable ss
  return ret;
}
// hook load module
int hook_sysmodule_load(uint16_t id) {
  int ret;
  ret = TAI_CONTINUE(int, load_hook, id);
  if (ret >= 0) { // load successful
    switch (id) {
      case SCE_SYSMODULE_SCREEN_SHOT:
        ss_disable_uid = 
          taiHookFunctionImport(&ss_disable_hook, // Output a reference
                        "AppName",                // Name of module being hooked
                        0xF26FC97D,               // NID specifying SceScreenShot
                        0x50AE9FF9,               // NID specifying sceScreenShotDisable
                        hook_ss_disable);         // Name of the hook function
        break;
      // you can consider other loaded modules too here ...
      default:
        break;
    }
  }
  return ret;
}
// hook unload module
int hook_sysmodule_unload(uint16_t id) {
  int ret;
  ret = TAI_CONTINUE(int, unload_hook, id);
  if (ret >= 0) { // unload successful
    switch (id) {
      case SCE_SYSMODULE_SCREEN_SHOT:
        if (ss_disable_uid >= 0) {
          taiHookRelease(ss_disable_uid, ss_disable_hook);
          ss_disable_uid = -1;
        }
        break;
      // you can consider other loaded modules too here ...
      default:
        break;
    }
  }
  return ret;
}
// our own plugin entry
int module_start(SceSize argc, const void *args) {
  ss_disable_uid = -1;
  taiHookFunctionImport(&load_hook,             // Output a reference
                        "AppName",              // Name of module being hooked
                        0x03FCF19D,             // NID specifying SceSysmodule
                        0x79A0160A,             // NID specifying sceSysmoduleLoadModule
                        hook_sysmodule_load);   // Name of the hook function
  taiHookFunctionImport(&unload_hook,           // Output a reference
                        "AppName",              // Name of module being hooked
                        0x03FCF19D,             // NID specifying SceSysmodule
                        0x31D87805,             // NID specifying sceSysmoduleUnloadModule
                        hook_sysmodule_unload); // Name of the hook function
  return SCE_KERNEL_START_SUCCESS;
}
```

### Loading a kernel plugin on demand

You can specify `suprx` to load with specific titles, but you cannot do so with
`skprx`. This is a limitation of the Vita kernel. A workaround is to use the
taiHEN APIs to manually load and unload the kernel module directly. Please note
this feature only works with unsafe homebrew enabled. Be aware that
`module_stop` of your user plugin is not automatically called so you should not
use that to cleanup your kernel plugin. Instead, your kernel plugin's
`module_start` can return `SCE_KERNEL_START_NO_RESIDENT` to be cleaned up
automatically after running. In the case that it is not possible, you should be
careful not to load the same kernel module twice.

It it important to remember to always clean up hooks and injections in
`module_stop` for kernel modules. You should be doing this for user modules as
well, but patches in user-space will be cleaned up by taiHEN when the process
exits. Patches in kernel will not be cleaned up automatically.

### Syscall stack limitations

When writing a kernel module that exposes new syscalls, know that the syscall
stack is only 4096 bytes. That means you might easily run out of space. You
should use `ksceKernelRunWithStack` to increase the stack size if needed.

### Unloading a kernel module that exposes syscalls

By default, the Vita does not allow unloading modules that exposes syscalls (you
will get `SCE_KERNEL_ERROR_MODULEMGR_IN_USE`). To get around this, you can hook
an override function in the module manager. This hook will be released when the
module is unloaded.

```c
// handles
static hook_ref_t unload_allowed_hook;
static SceUID unload_allowed_uid;
// patch
int unload_allowed_patched(void) {
  int ret;
  ret = TAI_CONTINUE(int, unload_allowed_hook);
  return 1; // always allowed
}
// kernel plugin entry
int module_start(SceSize argc, const void *args) {
  unload_allowed_uid = 
    taiHookFunctionImportForKernel(KERNEL_PID, 
                          &unload_allowed_hook,     // Output a reference
                          "SceKernelModulemgr",     // Name of module being hooked
                          0x11F9B314,               // NID specifying SceSblACMgrForKernel
                          0xBBA13D9C,               // Function NID
                          unload_allowed_patched);  // Name of the hook function
  // do other things here...
  return SCE_KERNEL_START_SUCCESS;
}
// cleanup
int module_stop(SceSize argc, const void *args) {
  // don't forget to clean up
  taiHookReleaseForKernel(unload_allowed_uid, unload_allowed_hook);
  // do other things here...
  return SCE_KERNEL_STOP_SUCCESS;
}
```

### Hooking a function while it is being called

There is currently a [bug](https://github.com/yifanlu/taiHEN/issues/12) in the
implementation where a crash may happen if you are hooking a function while it
is being used. Usually this doesn't happen (except by chance), but some
functions might be called in a tight loop. A temporary workaround is listed in 
the [issue tracker](https://github.com/yifanlu/taiHEN/issues/12).
