cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

SET(CMAKE_CXX_FLAGS_DEBUG "-O0")
SET(CMAKE_CXX_FLAGS_DEBUG "-g")

include(FetchContent)
FetchContent_Declare(
		yaml-cpp
		GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
		GIT_SHALLOW	ON
		GIT_TAG yaml-cpp-0.6.3
	)
FetchContent_GetProperties(yaml-cpp)
if(NOT yaml-cpp_POPULATED)
	message(STATUS "Populating yaml-cpp...")
	FetchContent_Populate(yaml-cpp)
	
	# Add here options for yaml-cpp building
    set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "disable yaml tests")
	set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "disable yaml tools")
	set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "disable yaml contrib")

	add_subdirectory(${yaml-cpp_SOURCE_DIR} ${yaml-cpp_BINARY_DIR})
	message(STATUS "Done.")
endif()

include_directories(BEFORE SYSTEM ${yaml-cpp_SOURCE_DIR} ${yaml-cpp_BINARY_DIR}/include)

include(FetchContent)
FetchContent_Declare(
		radiuspp
		GIT_REPOSITORY git@github.com:zstas/radiuspp.git
		GIT_SHALLOW	ON
	)
FetchContent_GetProperties(radiuspp)
if(NOT radiuspp_POPULATED)
	message(STATUS "Populating radiuspp...")
	FetchContent_Populate(radiuspp)

	add_subdirectory(${radiuspp_SOURCE_DIR} ${radiuspp_BINARY_DIR})
	message(STATUS "Done.")
endif()

include_directories(BEFORE SYSTEM ${radiuspp_SOURCE_DIR}/src)

# set the project name
project(ppp_cp)

file(GLOB SOURCES src/*.cpp)

# add the executable
add_executable(ppp_cp ${SOURCES})

target_link_libraries(ppp_cp PUBLIC boost_system)
target_link_libraries(ppp_cp PUBLIC yaml-cpp)
target_link_libraries(ppp_cp PUBLIC pthread)
target_link_libraries(ppp_cp PUBLIC vapiclient)
target_link_libraries(ppp_cp PUBLIC vppcom)
target_link_libraries(ppp_cp PUBLIC radiuspp)