cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(taihen)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O3 -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format -Wno-strict-aliasing -Wno-attributes -std=gnu99 -iquote ${CMAKE_CURRENT_SOURCE_DIR}/substitute/lib")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

# taihen parser options
set(INSTALL_ENABLED OFF CACHE BOOL "don't add parser to our install" FORCE)
set(USE_INBUILT_CTYPE ON CACHE BOOL "use inbuilt ctype for parser" FORCE)
set(USE_INBUILT_STRING ON CACHE BOOL "use inbuilt string for parser" FORCE)

include_directories(
  substitute
  taihen-parser/include
)

option(ENABLE_LOGGING "Set on to enable verbose logging" OFF)

add_definitions(-DNO_DYNAMIC_LINKER_STUFF)
add_definitions(-DNO_PTHREADS)

if (ENABLE_LOGGING)
  add_definitions(-DENABLE_LOGGING)
  add_definitions(-DTRANSFORM_DIS_VERBOSE)
endif(ENABLE_LOGGING)

add_subdirectory(taihen-parser)

add_executable(taihen
  hen.c
  module.c
  patches.c
  plugin.c
  proc_map.c
  taihen.c
  taihen-user.c
  posix-compat.c
  slab.c
  substitute/lib/hook-functions.c
  substitute/lib/jump-dis.c
  substitute/lib/strerror.c
  substitute/lib/transform-dis.c
  substitute/lib/cbit/vec.c
  substitute/lib/vita/execmem.c
)

target_link_libraries(taihen
  taihenparser
  gcc
  SceSysmemForDriver_stub
  SceSysmemForKernel_stub
  SceSysclibForDriver_stub
  SceCpuForKernel_stub
  SceCpuForDriver_stub
  SceSysrootForKernel_stub
  SceThreadmgrForDriver_stub
  SceModulemgrForKernel_stub
  SceModulemgrForDriver_stub
  SceIofilemgrForDriver_stub
  SceSblACMgrForDriver_stub
  SceSblAIMgrForDriver_stub
  SceDebugForDriver_stub
  SceCtrlForDriver_stub
)

vita_create_self(taihen.skprx taihen
  CONFIG ${CMAKE_SOURCE_DIR}/exports.yml
  UNSAFE
)
vita_create_stubs(taihen-stubs taihen ${CMAKE_SOURCE_DIR}/exports.yml
  KERNEL
)

install(DIRECTORY ${CMAKE_BINARY_DIR}/taihen-stubs/
  DESTINATION lib
  FILES_MATCHING PATTERN "*.a"
)

install(FILES taihen.h
  DESTINATION include
)
