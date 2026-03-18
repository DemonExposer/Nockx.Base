cmake_minimum_required(VERSION 3.20)
project(nockx-base)

find_package(OpenSSL REQUIRED)

add_library(nockx-base SHARED library.cpp)

target_link_libraries(nockx-base PRIVATE OpenSSL::SSL OpenSSL::Crypto)


set_property(TARGET nockx-base PROPERTY CXX_STANDARD 20)