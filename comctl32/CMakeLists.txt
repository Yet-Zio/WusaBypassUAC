cmake_minimum_required(VERSION 3.19)
project(comctl32)

set(CMAKE_CXX_STANDARD 17)

add_library(comctl32 SHARED targetver.h stdafx.h stdafx.cpp comctl32.h dllmain.cpp)

set_property(TARGET comctl32 PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded")