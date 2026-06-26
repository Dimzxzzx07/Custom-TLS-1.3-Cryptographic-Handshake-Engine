cmake_minimum_required(VERSION 3.10)
project(axon_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(axon_cpp STATIC
    src/engine.cpp
    src/handshake.cpp
    src/state.cpp
)

target_include_directories(cpp_core PUBLIC src)
