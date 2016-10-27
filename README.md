大変
================================================================================
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
`ux0:taihen/config.txt`. [Config format will be documented here.]

API
--------------------------------------------------------------------------------
taiHEN exports an API interface both to kernel and to user. This interface is
found in the [documentation pages](@ref taihen). You can either download the
release or build taiHEN yourself. After that, you can include `taihen.h` in your
project and link with `libtaihen_stub.a` and use `taihen.json` with vita-
toolchain.
