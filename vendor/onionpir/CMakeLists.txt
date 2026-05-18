cmake_minimum_required(VERSION 3.13)

# CMake 4.x compat: some bundled deps (e.g. older HEXL) still set 3.5-era policy
# defaults. Allow them to keep building under newer cmake.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# Set build type to Benchmark if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Benchmark)
endif()

# Compiler picked up from PATH. Load the desired toolchain before running
# cmake (e.g. `module load gcc/13.3.0`). Override with -DCMAKE_CXX_COMPILER=...
# if you want to pin a specific binary.

# Ask every target in this project to compile as C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)   # fail if the compiler can't do C++20
set(CMAKE_CXX_EXTENSIONS  OFF)        # use -std=c++20, not gnu++20

# Automatically enables all available optimizations for your local machine, including AVX2 and AVX512
set(CMAKE_CXX_FLAGS "-O3 -MD -march=native -mtune=native")  # Enable all optimizations

# Add perf when building in Debug mode
if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "-O2 -MD -pg -march=native -mtune=native")  # Enable profiling flags
endif()


# Intel HEXL is x86_64-only. Default ON for x86_64, OFF elsewhere (ARM, WASM).
# When OFF, the build uses a scalar shim under cpp/hexl_compat/ that mimics
# HEXL's API surface (NTT, Eltwise*, MinimalPrimitiveRoot) — see cpp/hexl_shim.cpp.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    set(_USE_HEXL_DEFAULT ON)
else()
    set(_USE_HEXL_DEFAULT OFF)
endif()
option(USE_HEXL "Enable Intel HEXL optimizations (x86_64 only)" ${_USE_HEXL_DEFAULT})

if (USE_HEXL)
    message(STATUS "HEXL support enabled.")
    add_compile_definitions(ONIONPIR_USE_HEXL)

    # HEXL_DIR can be overridden on the cmake line: -DHEXL_DIR=/path/to/cmake/hexl-1.2.6
    if (NOT HEXL_DIR)
        set(HEXL_DIR "/u/yuec12/OnionPIRv2/hexl_install/lib64/cmake/hexl-1.2.6")
    endif()

    find_package(HEXL REQUIRED)
    if(HEXL_FOUND)
        message(STATUS "HEXL found at: ${HEXL_DIR}")
    else()
        message(FATAL_ERROR "HEXL not found. Set -DHEXL_DIR=<path>, or pass -DUSE_HEXL=OFF to use the scalar fallback.")
    endif()
else()
    message(STATUS "HEXL support disabled — using scalar shim at cpp/hexl_compat/.")
endif()


# AVX-512 detection: -march=native already strips AVX-512 on CPUs that lack it,
# but some compilers (or older HEXL probes) still emit AVX-512 codegen unless
# explicitly disabled. Default NOAVX512=ON on non-x86 to avoid SIGILL on fresh
# clones; users on AVX-512 hosts can flip it off.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    option(NOAVX512 "Disable AVX-512" OFF)
else()
    option(NOAVX512 "Disable AVX-512" ON)
endif()
option(NOAVX2 "Disable AVX2" OFF)
if (NOAVX512 AND CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    message("Disabling AVX-512")
    add_compile_options(-mno-avx512f)
endif()
if (NOAVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    message("Disabling AVX2")
    add_compile_options(-mno-avx2)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")
set(IS_BENCHMARK_BUILD CMAKE_BUILD_TYPE STREQUAL "Benchmark")
if (${IS_BENCHMARK_BUILD})
    add_compile_definitions(_BENCHMARK)
endif ()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Onion-PIR)

# Build-time selector for the parameter set.
# Override on the cmake line:
#   cmake -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP ..
# Default is picked up from cpp/includes/database_constants.h when unset.
if (DEFINED ACTIVE_CONFIG)
    message(STATUS "ACTIVE_CONFIG = ${ACTIVE_CONFIG}")
    add_compile_definitions(ACTIVE_CONFIG=${ACTIVE_CONFIG})
endif()


# Source layout split for the two build targets:
#   ONIONPIR_CORE_SRC  = library-eligible sources (PIR engine + scalar HEXL shim
#                        if applicable). Excludes main.cpp / test scaffolding.
#   ONIONPIR_FFI_SRC   = C-ABI wrapper for Rust / Java consumers.
#   ONIONPIR_BIN_SRC   = additional sources for the Onion-PIR executable
#                        (main.cpp and the in-tree test harness under cpp/tests/).
file(GLOB ONIONPIR_CORE_SRC
    cpp/bv_keyswitch.cpp cpp/client.cpp cpp/gsw.cpp cpp/logging.cpp
    cpp/matrix.cpp cpp/pir.cpp cpp/query_queue.cpp cpp/rlwe.cpp cpp/server.cpp
    cpp/shared_key_store.cpp cpp/utils.cpp
)
if (NOT USE_HEXL)
    list(APPEND ONIONPIR_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/cpp/hexl_shim.cpp")
endif()

file(GLOB ONIONPIR_BIN_SRC cpp/main.cpp cpp/tests/*.cpp)
set(ONIONPIR_FFI_SRC "${CMAKE_CURRENT_SOURCE_DIR}/cpp/onion_ffi.cpp")

# Common include dirs reused by all targets below.
set(ONIONPIR_PUBLIC_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/cpp/includes")
if (NOT USE_HEXL)
    list(APPEND ONIONPIR_PUBLIC_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/cpp/hexl_compat")
endif()

# Executable target (Onion-PIR): core engine + test harness + main.
add_executable(Onion-PIR ${ONIONPIR_CORE_SRC} ${ONIONPIR_BIN_SRC})
target_include_directories(Onion-PIR PUBLIC ${ONIONPIR_PUBLIC_INCLUDES})
if (USE_HEXL AND HEXL_FOUND)
    target_link_libraries(Onion-PIR PUBLIC HEXL::hexl)
endif()
# Land the executable in the top-level build dir (e.g. build/Onion-PIR) so
# run.py and scripts/ find it at the same path as before this crate became a
# CMake subdirectory of the repo-root wrapper. CMAKE_BINARY_DIR is the top of
# the build tree whether configured here directly or via the wrapper.
set_target_properties(Onion-PIR PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Library target (onionpir): core engine + C ABI, for Rust / Java / native
# consumers. Disabled by default since the headline executable doesn't need it.
#   ONIONPIR_BUILD_FFI=ON       — build the library (Rust crate flips this on)
#   ONIONPIR_BUILD_SHARED=ON    — build as a .dylib / .so instead of .a
#                                  (Java JNA loads a shared library by name)
option(ONIONPIR_BUILD_FFI    "Build the onionpir library with C ABI" OFF)
option(ONIONPIR_BUILD_SHARED "Build onionpir as a shared library (default: static)" OFF)
if (ONIONPIR_BUILD_FFI)
    if (ONIONPIR_BUILD_SHARED)
        add_library(onionpir SHARED ${ONIONPIR_CORE_SRC} ${ONIONPIR_FFI_SRC})
    else()
        add_library(onionpir STATIC ${ONIONPIR_CORE_SRC} ${ONIONPIR_FFI_SRC})
    endif()
    target_include_directories(onionpir PUBLIC ${ONIONPIR_PUBLIC_INCLUDES})
    if (USE_HEXL AND HEXL_FOUND)
        target_link_libraries(onionpir PUBLIC HEXL::hexl)
    endif()
    # PIC so the static lib can be linked into shared libraries downstream
    # (Java JNA's .so/.dylib; Rust crates also commonly do).
    set_property(TARGET onionpir PROPERTY POSITION_INDEPENDENT_CODE ON)
    # Land the library in the top-level build dir (build-ffi/libonionpir.a,
    # build-shared/libonionpir.{so,dylib}) so build.rs, java/build.sh and the
    # tests/ffi_smoke.cpp recipe find it at the pre-restructure path.
    set_target_properties(onionpir PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
