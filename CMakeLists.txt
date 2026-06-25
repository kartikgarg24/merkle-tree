cmake_minimum_required(VERSION 3.15)
project(TinyMerkleTree VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directory
include_directories(include)

# Executable configuration
add_executable(merkle_demo src/main.cpp)