cmake_minimum_required(VERSION 3.6)
project(nic_monitor)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c data.c grab.c analyse.c state.c grab.h analyse.h state.h data.h)
add_executable(nic-monitor ${SOURCE_FILES})
target_link_libraries(nic-monitor -lpthread)