cmake_minimum_required(VERSION 3.10)

SET(CMAKE_CXX_FLAGS_DEBUG "-O0")
SET(CMAKE_CXX_FLAGS_DEBUG "-g")

# set the project name
project(bgp++)

file(GLOB SOURCES src/*.cpp)

# add the executable
add_executable(bgp++ ${SOURCES})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

target_link_libraries(bgp++ PUBLIC boost_system)
target_link_libraries(bgp++ PUBLIC pthread)