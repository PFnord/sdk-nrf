#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

zephyr_include_directories(./include)  # Needed for tc_util_user_override.h
zephyr_include_directories(~/ncs/zephyr/subsys/testsuite/ztest/include)  # Needed for tc_util_user_override.h

set(src_common src/main.c ${src_util})

project(persistent_key)

target_sources(app PRIVATE
  src/main.c
)
