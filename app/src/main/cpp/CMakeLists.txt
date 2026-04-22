cmake_minimum_required(VERSION 3.22.1)
project("pqzkesim_jni" LANGUAGES C CXX)

# ============================================================
# 1. 编译器设置与安全选项
# ============================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17) # OpenCV 通常需要 C++ 11 以上
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
else()
    add_compile_options(-O0 -g)
endif()

# ============================================================
# 2. 库导入路径配置
# ============================================================
# 静态库目录：D:\programa\app\src\main\cpp\libs\arm64-v8a
set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI})

# 动态库目录 (用于 OpenCV)：app/src/main/jniLibs/arm64-v8a
set(JNI_LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

# 2.1 导入算法核心静态库 (liboqs, openssl)
add_library(liboqs STATIC IMPORTED)
set_target_properties(liboqs PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/liboqs.a)

add_library(crypto_static STATIC IMPORTED)
set_target_properties(crypto_static PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/libcrypto.a)

add_library(ssl_static STATIC IMPORTED)
set_target_properties(ssl_static PROPERTIES IMPORTED_LOCATION ${LIBS_DIR}/libssl.a)

# 2.2 导入 OpenCV 动态库
add_library(opencv_java4 SHARED IMPORTED)
set_target_properties(opencv_java4 PROPERTIES IMPORTED_LOCATION ${JNI_LIBS_DIR}/libopencv_java4.so)

# ============================================================
# 3. 头文件与源文件
# ============================================================
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/algebra
    ${CMAKE_CURRENT_SOURCE_DIR}/internal
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/tee
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../opencv/native/jni/include
)

# 汇总所有源文件
set(PQZK_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/native-lib.cpp         # 将 JNI 接口直接合入主库
    ${CMAKE_CURRENT_SOURCE_DIR}/pq_zk_esim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/pq-zk-crypto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/algebra/pq_zk_poly.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/pq_zk_nvram.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tee/pqzk_merkle.c
)

# ============================================================
# 4. 构建与链接
# ============================================================
# 构建唯一的共享库：pqzkesim
# 这样在 Java 层只需 System.loadLibrary("pqzkesim") 即可
add_library(pqzkesim SHARED ${PQZK_SOURCES})

target_link_libraries(pqzkesim
    # 静态链接
    liboqs
    ssl_static
    crypto_static
    # 动态链接 OpenCV
    opencv_java4
    # 系统库
    log
    android
    jnigraphics # 用于处理 Bitmap
    m
    atomic
)