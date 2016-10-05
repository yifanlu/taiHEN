cmake_minimum_required(VERSION 2.8)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")

project(taiHEN)

set(CMAKE_C_FLAGS "-Wl,-q -Wall -O3 -Wno-unused-variable -Wno-unused-but-set-variable -std=gnu99 -iquote ${CMAKE_CURRENT_SOURCE_DIR}/substitute/lib")
set(CMAKE_EXE_LINKER_FLAGS "-nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

include_directories(
	substitute
	tests/include
)

link_directories(
	${CMAKE_CURRENT_BINARY_DIR}
)

include(ExternalProject)
ExternalProject_Add(kernel
	SOURCE_DIR ${CMAKE_SOURCE_DIR}/kernel
	CONFIGURE_COMMAND ""
	BUILD_IN_SOURCE 1
	BUILD_COMMAND make
	PREFIX=${CMAKE_CURRENT_BINARY_DIR}
	INSTALL_COMMAND ""
)

add_definitions(-DNO_DYNAMIC_LINKER_STUFF)
add_definitions(-DNO_PTHREADS)

add_executable(taihen.elf
	module.c
	patches.c
	proc_map.c
	taihen.c
	posix-compat.c
	substitute/lib/hook-functions.c
	substitute/lib/jump-dis.c
	substitute/lib/strerror.c
	substitute/lib/transform-dis.c
	substitute/lib/cbit/vec.c
	substitute/lib/vita/execmem.c
)

target_link_libraries(taihen.elf
	gcc
	SceStdioTMP_KERNEL_stub
	SceKernelThreadMgrTMP_KERNEL_stub
	SceSysmemTMP_KERNEL_stub
)
add_dependencies(taihen.elf kernel)

add_custom_target(taihen.skprx ALL
	COMMAND vita-elf-create taihen.elf taihen.velf ${CMAKE_SOURCE_DIR}/kernel/kernel.json
	COMMAND vita-make-fself taihen.velf taihen.skprx
)
add_dependencies(taihen.skprx taihen.elf)
