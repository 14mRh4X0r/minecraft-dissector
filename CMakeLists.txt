# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
# Copyright 2020 Willem Mulder <14mRh4X0r@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.1)
cmake_policy(SET CMP0048 NEW)

project("Minecraft Dissector"
    VERSION 0.1.0
    DESCRIPTION "Minecraft protocol dissector for Minecraft"
    LANGUAGES C
)

find_package(Wireshark CONFIG REQUIRED)

if(NOT Wireshark_PLUGINS_ENABLED)
    message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra -Wpedantic -Werror=implicit-function-declaration ${CMAKE_C_FLAGS}")
endif()

add_definitions(-DVERSION=\"${PROJECT_VERSION}\")
add_definitions(-DHAVE_LIBGNUTLS) # TODO find a way to check whether GnuTLS is available

add_custom_command(OUTPUT generated.h COMMAND node generate.js > generated.h WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_library(minecraft MODULE packet-minecraft.c generated.h)
set_target_properties(minecraft PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(minecraft epan)

install(TARGETS minecraft
    LIBRARY DESTINATION "${Wireshark_PLUGIN_INSTALL_DIR}/epan" NAMELINK_SKIP
)
