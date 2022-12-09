cmake_minimum_required(VERSION 3.4.1)

link_directories(BEFORE ${TONGSUO_HOME}/lib/)

add_library(conscrypt_jni
            SHARED
            ../common/src/jni/main/cpp/conscrypt/compatibility_close_monitor.cc
            ../common/src/jni/main/cpp/conscrypt/jniload.cc
            ../common/src/jni/main/cpp/conscrypt/jniutil.cc
            ../common/src/jni/main/cpp/conscrypt/native_crypto.cc
            ../common/src/jni/main/cpp/conscrypt/netutil.cc
            )
include_directories(../common/src/jni/main/include/
                    ../common/src/jni/unbundled/include/
                    ${TONGSUO_HOME}/include/)

find_library(android-log-lib log)
target_link_libraries(conscrypt_jni ${android-log-lib} ssl crypto)

add_definitions(-DANDROID
                -fvisibility=hidden
                -DOPENSSL_SMALL
                -D_XOPEN_SOURCE=700
                -Wno-unused-parameter
                # The following two lines are taken from BoringSSL's build file.  As written there:
                #
                # Clang's -Wtautological-constant-compare is far too aggressive and does not
                # account for, say, wanting the same code to work on both 32-bit and 64-bit
                # platforms.
                #
                # TODO: Remove these when the NDK no longer includes a version that has
                # -Wtautological-constant-compare enabled as part of -Wall
                -Wno-tautological-constant-compare
                -Wtautological-constant-out-of-range-compare
                -Wno-deprecated-declarations)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -march=armv8-a+crypto")
endif()

add_subdirectory(${BORINGSSL_HOME} ${CMAKE_CURRENT_BINARY_DIR}/boringssl)
