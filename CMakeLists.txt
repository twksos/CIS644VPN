cmake_minimum_required(VERSION 3.5)
project(CIS644VPN)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    cli.c
    cli.h
    crypt.c
    crypt.h
    srv.c
    srv.h
    tunproxy.c
    util.c
    util.h)

add_executable(CIS644VPN ${SOURCE_FILES})