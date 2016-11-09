cmake_minimum_required(VERSION 2.8)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")
set(CMAKE_RANLIB "arm-vita-eabi-ranlib")

project(taiHEN)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format -Wno-strict-aliasing -Wno-attributes -std=gnu99 -iquote ${CMAKE_CURRENT_SOURCE_DIR}/substitute/lib")
set(CMAKE_EXE_LINKER_FLAGS "-nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

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
add_definitions(-D__VITA_KERNEL__)

if (ENABLE_LOGGING)
	add_definitions(-DENABLE_LOGGING)
	add_definitions(-DTRANSFORM_DIS_VERBOSE)
endif(ENABLE_LOGGING)

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
	taihenparser
	gcc
	SceSysmemForDriver_stub
	SceSysmemForKernel_stub
	SceSysclibForDriver_stub
	SceCpuForKernel_stub
	SceCpuForDriver_stub
	SceSysrootForKernel_stub
	SceThreadmgrForKernel_stub
	SceThreadmgrForDriver_stub
	SceModulemgrForKernel_stub
	SceModulemgrForDriver_stub
	SceIofilemgrForDriver_stub
	SceSblACMgrForDriver_stub
	SceDebugForDriver_stub
)

add_custom_target(taihen.skprx ALL
	COMMAND vita-elf-create -e ${CMAKE_SOURCE_DIR}/exports.yml taihen.elf taihen.velf
	COMMAND vita-make-fself taihen.velf taihen.skprx
)
add_dependencies(taihen.skprx taihen.elf)

add_custom_target(taihen-libs ALL
	COMMAND vita-elf-export kernel taihen.elf ${CMAKE_SOURCE_DIR}/exports.yml taihen.json
	COMMAND vita-libs-gen taihen.json taihen-libs
	COMMAND make -C taihen-libs
)

add_dependencies(taihen-libs taihen.elf)

install(DIRECTORY ${CMAKE_BINARY_DIR}/taihen-libs/
		DESTINATION lib
		FILES_MATCHING PATTERN "*.a")

install(FILES ${CMAKE_BINARY_DIR}/taihen.json
		DESTINATION share/imports)

install(FILES taihen.h
		DESTINATION include)

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	if (NOT DEFINED ENV{VITASDK})
		message(FATAL_ERROR "Error: the VITASDK environment variable is not set.")
	endif()
	set(CMAKE_INSTALL_PREFIX "$ENV{VITASDK}/arm-vita-eabi" CACHE PATH "default install path" FORCE)
endif()
