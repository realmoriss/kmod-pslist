cmake_minimum_required(VERSION 2.8.8)
project(modules)

set(LINUX_ROOT ${modules_SOURCE_DIR}/../linux/)
set(TOOLCHAINS_VERSION 7.3.1)
set(TOOLCHAINS_ARCH aarch64-linux-gnu)
set(TOOLCHAINS_ROOT ${modules_SOURCE_DIR}/../gcc-linaro-${TOOLCHAINS_ARCH}/)

set(LINUX_ARCH arm64)
set(LINUX_BOARD_PLATFORM bcmrpi3)

set(KERNEL_HEADERS
        ${LINUX_ROOT}/include
        ${LINUX_ROOT}/include/uapi
        ${LINUX_ROOT}/include/generated/uapi
        ${LINUX_ROOT}/arch/${LINUX_ARCH}/include
        ${LINUX_ROOT}/arch/${LINUX_ARCH}/include/uapi
        ${LINUX_ROOT}/arch/${LINUX_ARCH}/include/generated
        ${LINUX_ROOT}/arch/${LINUX_ARCH}/include/generated/uapi
)

set(MODULE_SOURCES linux_pslist.c)

set(CMAKE_C_COMPILER ${TOOLCHAINS_ROOT}/bin/${TOOLCHAINS_ARCH}-gcc)

include_directories(${TOOLCHAINS_ROOT}/lib/gcc/${TOOLCHAINS_ARCH}/${TOOLCHAINS_VERSION}/include)
include_directories(${KERNEL_HEADERS})

add_definitions(-nostdinc -isystem ${TOOLCHAINS_ROOT}/lib/gcc/${TOOLCHAINS_ARCH}/${TOOLCHAINS_VERSION}/include)
add_definitions(-include ${LINUX_ROOT}/include/linux/kconfig.h)
add_definitions(-D__KERNEL__)
add_definitions(-DMODULE)
add_definitions(-std=c89)

add_custom_target(modules COMMAND $(MAKE) -C ${modules_SOURCE_DIR} PWD=${modules_SOURCE_DIR}
        CROSS_COMPILE=${TOOLCHAINS_ROOT}/bin/${TOOLCHAINS_ARCH}- LINUX_KERNEL=${LINUX_ROOT}
        ARCH=${LINUX_ARCH})

add_custom_target(kernel COMMAND $(MAKE) -C ${modules_SOURCE_DIR} PWD=${modules_SOURCE_DIR}
        CROSS_COMPILE=${TOOLCHAINS_ROOT}/bin/${TOOLCHAINS_ARCH}- LINUX_KERNEL=${LINUX_ROOT}
        ARCH=${LINUX_ARCH} BOARD_PLATFORM=${LINUX_BOARD_PLATFORM} kernel)

add_library(dummymod ${MODULE_SOURCES})