cmake_minimum_required(VERSION 3.12)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 99)

# CMake modules
include(CMakePushCheckState)
include(CheckCXXSourceCompiles)
include(GNUInstallDirs)

# Extra modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
include(PoseidonMacros)

#select COMPILER
option(CROSS_COMPILE_ARRCH64 "Compile with aarch64" OFF)
message(STATUS "CROSS_COMPILE_ARRCH64: ${CROSS_COMPILE_ARRCH64}")
if(CROSS_COMPILE_ARRCH64)
    SET(CMAKE_C_COMPILER /data/gcc-arm-11.2/bin/aarch64-none-linux-gnu-gcc)
    SET(CMAKE_CXX_COMPILER /data/gcc-arm-11.2/bin/aarch64-none-linux-gnu-g++)
    include_directories(/data/gmp-arm/gmp-6.3.0-install/include)
    link_directories(/data/gmp-arm/gmp-6.3.0-install/lib)
endif ()

project(Poseidon VERSION 1.0.0 LANGUAGES CXX C)

# 根据ASAN的值来设置编译器标志  
option(ASAN "Enable AddressSanitizer" OFF)  
if(ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize-recover=address -fno-stack-protector -fno-omit-frame-pointer")
    message(STATUS "AddressSanitizer enabled.") 
else()
    message(STATUS "AddressSanitizer disabled.")
endif()

# [option] CMAKE_BUILD_TYPE (default: "Release")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
            STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make the install target depend on the all target (required by vcpkg)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY OFF)

set(POSEIDON_USE_CXX17_OPTION_STR "Use C++17")
option(POSEIDON_USE_CXX17 ${POSEIDON_USE_CXX17_OPTION_STR} ON)
message(STATUS "POSEIDON_USE_CXX17: ${POSEIDON_USE_CXX17}")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG -fPIC -pthread ")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG -fPIC -pthread ")
SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lgmp  -fopenmp")

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

message("-- Install Path: ${CMAKE_INSTALL_PREFIX}")
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Source Tree
set(POSEIDON_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR})
set(POSEIDON_CONFIG_H_IN_FILENAME ${POSEIDON_INCLUDES_DIR}/src/poseidon/util/config.h.in)

# Build tree
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(POSEIDON_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/POSEIDONConfig.cmake)
set(POSEIDON_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/poseidon/util/config.h)
set(POSEIDON_THIRDPARTY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Install
set(POSEIDON_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake)
set(POSEIDON_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR})

#########################
# External dependencies #
#########################

# 目前只添加了zstd和zlib两个压缩库
# [option] POSEIDON_BUILD_DEPS (default: OFF)
# Download and build missing dependencies, throw error if disabled.
set(POSEIDON_BUILD_DEPS_OPTION_STR "Automatically download and build unmet dependencies")
option(POSEIDON_BUILD_DEPS ${POSEIDON_BUILD_DEPS_OPTION_STR} ON)
message(STATUS "POSEIDON_BUILD_DEPS: ${POSEIDON_BUILD_DEPS}")

if(POSEIDON_BUILD_DEPS)
    include(FetchContent)
    mark_as_advanced(FETCHCONTENT_BASE_DIR)
    mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_QUIET)
endif()

# [option] POSEIDON_USE_ZLIB (default: ON)
set(POSEIDON_USE_ZLIB_OPTION_STR "Use ZLIB for compressed serialization")
option(POSEIDON_USE_ZLIB ${POSEIDON_USE_ZLIB_OPTION_STR} OFF)
message(STATUS "POSEIDON_USE_ZLIB: ${POSEIDON_USE_ZLIB}")

if(POSEIDON_USE_ZLIB)
    if(POSEIDON_BUILD_DEPS)
        message(STATUS "ZLIB: download ...")
        poseidon_fetch_thirdparty_content(ExternalZLIB)
        set(zlib "zlibstatic")
    else()
        find_package(ZLIB 1)
        if(NOT ZLIB_FOUND)
            message(FATAL_ERROR "ZLIB: not found")
        else()
            message(STATUS "ZLIB: found")
        endif()
        set(zlib "ZLIB::ZLIB")
    endif()
endif()

# [option] POSEIDON_USE_ZSTD (default: ON)
set(POSEIDON_USE_ZSTD_OPTION_STR "Use Zstandard for compressed serialization")
option(POSEIDON_USE_ZSTD ${POSEIDON_USE_ZSTD_OPTION_STR} OFF)
message(STATUS "POSEIDON_USE_ZSTD: ${POSEIDON_USE_ZSTD}")

if(POSEIDON_USE_ZSTD)
    if(POSEIDON_BUILD_DEPS)
        message(STATUS "Zstandard: download ...")
        poseidon_fetch_thirdparty_content(ExternalZSTD)
        set(zstd_static "libzstd_static")
    else()
        find_package(zstd CONFIG)
        if(NOT zstd_FOUND)
            message(FATAL_ERROR "Zstandard: not found")
        else()
            if(TARGET zstd::libzstd_static)
                set(zstd_static "zstd::libzstd_static")
            elseif(TARGET libzstd)
                get_target_property(libzstd_type libzstd TYPE)
                if(libzstd_type STREQUAL "STATIC_LIBRARY")
                    set(zstd_static "libzstd")
                    message(STATUS "Zstandard: found")
                else()
                    message(FATAL_ERROR "Zstandard: must be static")
                endif()
            elseif(TARGET zstd::libzstd_shared)
                message(FATAL_ERROR "Zstandard: must be static")
            else()
                message(FATAL_ERROR "Zstandard: not found")
            endif()
        endif()
    endif()
endif()

# [option] POSEIDON_USE_HARDWARE (default: OFF)
# If you turn on POSEIDON_USE_HARDWARE, you need to install poseidon_hardware first.
option(POSEIDON_USE_HARDWARE OFF)
message(STATUS "POSEIDON_USE_HARDWARE: ${POSEIDON_USE_HARDWARE}")
if(POSEIDON_USE_HARDWARE)
    set(USING_HARDWARE ON)
endif()
add_subdirectory(src/poseidon)

# [option] POSEIDON_USE_MSGSL (default: ON)
set(POSEIDON_USE_MSGSL_OPTION_STR "Use Microsoft GSL")
option(POSEIDON_USE_MSGSL ${POSEIDON_USE_MSGSL_OPTION_STR} ON)
message(STATUS "POSEIDON_USE_MSGSL: ${POSEIDON_USE_MSGSL}")

if(POSEIDON_USE_MSGSL)
    if(POSEIDON_BUILD_DEPS)
        message(STATUS "Microsoft GSL: download ...")
        poseidon_fetch_thirdparty_content(ExternalMSGSL)
    else()
        find_package(Microsoft.GSL 4 CONFIG)
        if(NOT Microsoft.GSL_FOUND)
            message(FATAL_ERROR "Microsoft GSL: not found")
        else()
            message(STATUS "Microsoft GSL: found")
        endif()
    endif()
endif()

# [option] POSEIDON_BUILD_EXAMPLES (default: ON)
option(POSEIDON_BUILD_EXAMPLES "Build examples for POSEIDON" ON)
message(STATUS "POSEIDON_BUILD_EXAMPLES: ${POSEIDON_BUILD_EXAMPLES}")
if(POSEIDON_BUILD_EXAMPLES)
    add_subdirectory(examples/bfv)
    add_subdirectory(examples/bgv)
    add_subdirectory(examples/ckks)
endif()

# Create the config file
configure_file(${POSEIDON_CONFIG_H_IN_FILENAME} ${POSEIDON_CONFIG_H_FILENAME})
install(
    FILES ${POSEIDON_CONFIG_H_FILENAME}
    DESTINATION ${POSEIDON_INCLUDES_INSTALL_DIR}/poseidon/util)

add_library(poseidon_shared SHARED ${POSEIDON_SOURCE_FILES})    
target_include_directories(poseidon_shared PUBLIC ${POSEIDON_INCLUDES_DIR}/src)
target_link_libraries(poseidon_shared PRIVATE gmp)
if(POSEIDON_USE_HARDWARE)    
    target_link_libraries(poseidon_shared PUBLIC poseidon_hardware)
endif()

if(POSEIDON_USE_MSGSL)
    if(POSEIDON_BUILD_DEPS)
        target_include_directories(poseidon_shared PUBLIC $<BUILD_INTERFACE:${msgsl_SOURCE_DIR}/include>)
    else()
        target_link_libraries(poseidon_shared PUBLIC Microsoft.GSL::GSL)
    endif()
endif()

if(POSEIDON_USE_ZLIB)
    target_link_libraries(poseidon_shared PRIVATE ${zlib})
    target_include_directories(poseidon_shared PRIVATE $<BUILD_INTERFACE:${zlib_SOURCE_DIR}>)
    target_include_directories(poseidon_shared PRIVATE $<BUILD_INTERFACE:$<TARGET_PROPERTY:${zlib},BINARY_DIR>>)
endif()

if(POSEIDON_USE_ZSTD)
    target_include_directories(poseidon_shared PRIVATE $<BUILD_INTERFACE:${zstd_SOURCE_DIR}/lib>)
    target_include_directories(poseidon_shared PRIVATE $<BUILD_INTERFACE:${zstd_SOURCE_DIR}/lib/common>)
    target_link_libraries(poseidon_shared PRIVATE ${zstd_static})
endif()


# set the real path
if(DEFINED ENV{Torch_DIR})
    set(torch_path "$ENV{Torch_DIR}")
else()
    set(torch_path "path/to/your/pytorch/torch")
endif()
if(NOT EXISTS ${torch_path})
  message(FATAL_ERROR "please set correct torch_path")
endif()
include_directories(${torch_path}/include)
link_directories(${torch_path}/lib)

# set the real path
if(DEFINED ENV{TORCH_MLU_HOME})
    set(torch_mlu_path "$ENV{TORCH_MLU_HOME}")
else()
    set(torch_mlu_path "path/to/your/torch_mlu")
endif()
if(NOT EXISTS ${torch_mlu_path})
  message(FATAL_ERROR "please set correct torch_mlu_path")
endif()

# set the real path
if(DEFINED ENV{NEUWARE_HOME})
    set(neuware_home "$ENV{NEUWARE_HOME}")
else()
    set(neuware_home "path/to/your/neuware_home")
endif()
if(NOT EXISTS ${neuware_home})
  message(FATAL_ERROR "please set correct neuware_home")
endif()

include_directories(${torch_mlu_path}/csrc)
include_directories(${neuware_home}/include)

link_directories(${torch_mlu_path}/csrc/lib)
link_directories(${neuware_home}/lib64)

target_link_libraries(poseidon_shared PUBLIC "-Wl,--no-as-needed" torch_mlu "-Wl,--as-needed")
target_link_libraries(poseidon_shared PUBLIC pthread)
target_link_libraries(poseidon_shared PUBLIC cnrt)
target_link_libraries(poseidon_shared PUBLIC torch torch_cpu c10 dl util)


# set(TCIM_LITE_LIB_DIR /usr/local/lib/python3.9/dist-packages/tcim_lite/lib)
# target_link_directories(poseidon_shared PUBLIC ${TCIM_LITE_LIB_DIR})
# target_link_libraries(poseidon_shared PUBLIC tcim_runtime_lite)

if(POSEIDON_BUILD_DEPS)
    # MSGSL
    if(POSEIDON_USE_MSGSL)
        install(
            DIRECTORY ${msgsl_SOURCE_DIR}/include/gsl
            DESTINATION ${POSEIDON_INCLUDES_INSTALL_DIR})
    endif()
endif()

install(
        TARGETS poseidon_shared
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
)
