cmake_minimum_required(VERSION 3.19)
project(WusaBypassUAC)

set(CMAKE_CXX_STANDARD 17)

set(SOURCE_FILES comctl32.cpp stdafx.cpp)

add_executable(WusaBypassUAC main.cpp ${SOURCE_FILES})

set_property(TARGET WusaBypassUAC PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded")

target_link_libraries(WusaBypassUAC Ws2_32.lib Crypt32.lib Cabinet.lib)
