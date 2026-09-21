cmake_minimum_required(VERSION 3.20)

# Independent downstream consumer of the installed Network Recovery Planner
# package. This project lives outside the planner source tree on purpose: it
# proves that the installed headers, library and package config are sufficient.
project(nrp_downstream_consumer
  VERSION 1.0.0
  DESCRIPTION "Downstream consumer of the installed Network Recovery Planner package"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(NetworkRecoveryPlanner CONFIG REQUIRED)

add_executable(nrp_consumer main.cpp)
target_link_libraries(nrp_consumer PRIVATE nrp::network_recovery_planner)

if(MSVC)
  target_compile_options(nrp_consumer PRIVATE /W4 /permissive-)
endif()
