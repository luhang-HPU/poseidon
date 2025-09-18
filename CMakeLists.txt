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

project(Poseidon VERSION 1.0.0 LANGUAGES CXX C)

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

# Create the config file
configure_file(${POSEIDON_CONFIG_H_IN_FILENAME} ${POSEIDON_CONFIG_H_FILENAME})
install(
    FILES ${POSEIDON_CONFIG_H_FILENAME}
    DESTINATION ${POSEIDON_INCLUDES_INSTALL_DIR}/poseidon/util)

add_library(poseidon_shared STATIC ${POSEIDON_SOURCE_FILES})    
target_include_directories(poseidon_shared PUBLIC ${POSEIDON_INCLUDES_DIR}/src)
target_link_libraries(poseidon_shared PRIVATE gmp)

if(POSEIDON_USE_MSGSL)
    if(POSEIDON_BUILD_DEPS)
        target_include_directories(poseidon_shared PUBLIC $<BUILD_INTERFACE:${msgsl_SOURCE_DIR}/include>)
    else()
        target_link_libraries(poseidon_shared PUBLIC Microsoft.GSL::GSL)
    endif()
endif()

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
