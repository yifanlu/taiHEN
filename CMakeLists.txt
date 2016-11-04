cmake_minimum_required(VERSION 2.8)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")
set(CMAKE_RANLIB "arm-vita-eabi-ranlib")

project(taiHEN)

set(CMAKE_C_FLAGS "-Wl,-q -Wall -O3 -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format -Wno-strict-aliasing -Wno-attributes -std=gnu99 -iquote ${CMAKE_CURRENT_SOURCE_DIR}/substitute/lib")
set(CMAKE_EXE_LINKER_FLAGS "-nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

include_directories(
	substitute
	taihen-parser/include
)

link_directories(
	${CMAKE_CURRENT_BINARY_DIR}
)

add_definitions(-DNO_DYNAMIC_LINKER_STUFF)
add_definitions(-DNO_PTHREADS)
add_definitions(-DENABLE_LOGGING)
add_definitions(-D__VITA_KERNEL__)
add_definitions(-DTRANSFORM_DIS_VERBOSE)

add_subdirectory(taihen-parser)

add_executable(taihen.elf
	hen.c
	module.c
	patches.c
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

target_link_libraries(taihen.elf
	taihenconfig
	gcc
	SceKernelThreadMgr_stub
	SceSysmem_stub
	SceKernelModulemgr_stub
	SceIofilemgr_stub
	SceStdio_stub
	SceSblSsMgr_stub
	SceSblACMgr_stub
)

add_custom_target(taihen.skprx ALL
	COMMAND vita-elf-create -e ${CMAKE_SOURCE_DIR}/exports.yml taihen.elf taihen.velf
	COMMAND vita-make-fself taihen.velf taihen.skprx
)
add_dependencies(taihen.skprx taihen.elf)
