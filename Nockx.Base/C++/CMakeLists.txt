cmake_minimum_required(VERSION 4.0)
project(nockx-base)

set(CMAKE_CXX_STANDARD 20)

set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
set(OPENSSL_INCLUDE_DIR "/opt/homebrew/opt/openssl@3/include")
set(OPENSSL_LIB_DIR "/opt/homebrew/opt/openssl@3/lib")

find_package(OpenSSL REQUIRED)

add_library(nockx-base SHARED library.cpp)

target_include_directories(nockx-base PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(nockx-base PRIVATE OpenSSL::Crypto OpenSSL::SSL)
