#!/bin/bash

export NFF_GO=/opt/nff-go
export RTE_TARGET=x86_64-native-linuxapp-gcc

DPDK_DIR=dpdk
DPDK_INSTALL_DIR=${RTE_TARGET}-install
export RTE_SDK="${NFF_GO}"/dpdk/${DPDK_DIR}/${DPDK_INSTALL_DIR}/usr/local/share/dpdk

export CGO_LDFLAGS_ALLOW='-Wl,--((no-)?whole-archive|((start|end)-group))'
export CGO_CFLAGS="-I${RTE_SDK}/${RTE_TARGET}/include -O3 -std=gnu11 -m64 -pthread -march=native -mno-fsgsbase -mno-f16c -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_F16C -include rte_config.h -Wno-deprecated-declarations"
export CGO_LDFLAGS="-L${RTE_SDK}/${RTE_TARGET}/lib -Wl,--no-as-needed -Wl,-export-dynamic"
