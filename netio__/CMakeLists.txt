
#project(netio__)

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})

SET(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "${CMAKE_SOURCE_DIR}/cryptoTools/thirdparty/linux/boost")

find_package(Boost REQUIRED program_options COMPONENTS)

add_executable(netio__  ${SRCS})

target_link_libraries(netio__ libOTe_Tests ${Boost_LIBRARIES} tests_cryptoTools)