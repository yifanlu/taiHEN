大変
================================================================================
[![Build Status](https://travis-ci.org/yifanlu/taiHEN.svg?branch=master)](https://travis-ci.org/yifanlu/taiHEN)

taiHEN is a CFW framework for PS Vita&trade;. When loaded with a kernel exploit,
it acts as a common substrate for patching the system. taiHEN provides three
main facilities:

1. It disables code signature checks to allow unsigned executables.
2. It exposes kernel peek/poke syscalls to user applications and allows loading 
   of kernel modules.
3. Most importantly, it provides an API for hooking and replacing functions 
   based off of [substitute](http://github.com/comex/substitute).

The last point means that developers can add custom patches to kernel, system
applications, and games alike.

Building
--------------------------------------------------------------------------------
To build, you need the latest version of the
[toolchain](https://github.com/vitasdk/buildscripts) with kernel support. Then
just use CMake to build.

```bash
$ mkdir build && cd build
$ cmake ../
$ make
```

Installation
--------------------------------------------------------------------------------
taiHEN requires a separate kernel exploit to run. Once the exploit loads
`taihen.skprx` to the kernel, taiHEN will take care of the rest. Please refer to
documentations for the exploit for more information.

Plugins
--------------------------------------------------------------------------------
Plugins are loaded either into kernel after taiHEN is loaded or on demand when
an application is launched. taiHEN reads the configuration file in
`ux0:tai/config.txt`.

The configuration that determines the plugins to load and the load order can
be found in `ux0:tai/config.txt`. The format is very simple and self
explanatory.

```text
# ignored line starting with #
# Kernel plugins are started with taiHEN and are in this section
*KERNEL
ux0:app/MLCL00001/henkaku.skprx
ux0:path/to/another.skprx
ux0:tai/plugin3.skprx
ux0:data/tai/plugin4.skprx
ux0:data/tai/plugin5.skprx
# titleid for SceSettings
*NPXS10015
ux0:app/MLCL00001/henkaku.suprx
ux0:data/tai/some_settings_plugin.suprx
# titleid for Package Installer
*NPXS10031
ux0:path/to/some_pkg_installer_plgin.suprx
# titleid for SceShell is special (does not follow the XXXXYYYYY format)
*main
ux0:app/MLCL00001/henkaku.skprx
ux0:data/tai/shell_plgin.skprx
```

The key things to note are

1. `#` begins a comment, `*` begins a section, and any other character begins
a path.
2. `KERNEL` is a special section name denoting to load a kernel plugin when
taiHEN is started up. All other section names are the title id of the
application/game in which to load the plugin at startup. Note that SceShell
has a special title id of `main`.
3. In each section, there is a list of plugin paths that will be loaded in
order. Paths can be anywhere but it is recommended that plugins reside in
`ux0:tai` or `ux0:data/tai`. It is valid to have one plugin in multiple
sections but the developer must ensure that the plugin knows which application
it is loaded in if it needs to do things differently.

API
--------------------------------------------------------------------------------
taiHEN exports an API interface both to kernel and to user. This interface is
found in the [documentation pages](@ref taihen). You should also read the 
[usage guide](USAGE.md) for more details. You can either download the release 
or build taiHEN yourself. After that, you can include `taihen.h` in your 
project and link with `libtaihen_stub.a` (for user modules) or 
`libtaihen_kernel_stub.a` (for kernel modules).
