cmake_minimum_required(VERSION 3.0.0)
project(dns-poisoner VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 11)

include(CTest)
enable_testing()

include(FindPCAP.cmake)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(dns-poisoner main.cpp NetworkEngine.cpp TcpStack.cpp UdpStack.cpp)
target_link_libraries(dns-poisoner ${PCAP_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
