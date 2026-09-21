cmake_minimum_required(VERSION 3.20)

project(NetworkRecoveryPlanner
  VERSION 1.0.0
  DESCRIPTION "Recovery plan computation and validation runtime for disrupted network fabrics"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(NRP_BUILD_TESTS "Build the Network Recovery Planner test suites" ON)
option(NRP_BUILD_TOOLS "Build CLI tools and the framed-protocol server" ON)
option(NRP_BUILD_EXAMPLES "Build examples" ON)
option(NRP_WERROR "Treat compiler warnings as errors" OFF)
option(NRP_ASAN "Enable AddressSanitizer (MSVC /fsanitize=address or GCC/Clang -fsanitize=address)" OFF)
option(NRP_STRICT "Enable the strict warning set" ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Warnings and sanitizer flags
#
# Applied directly to each target rather than through an interface library, so
# the installed package exports no build-only dependency.
# ---------------------------------------------------------------------------
function(nrp_apply_warnings target)
  if(MSVC)
    if(NRP_STRICT)
      target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor)
    endif()
    if(NRP_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
  else()
    if(NRP_STRICT)
      target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion
        -Wsign-conversion -Wold-style-cast -Wcast-qual -Wnon-virtual-dtor -Woverloaded-virtual)
    endif()
    if(NRP_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
  if(NRP_ASAN)
    if(MSVC)
      target_compile_options(${target} PRIVATE /fsanitize=address)
      target_compile_definitions(${target} PRIVATE NRP_ASAN_ENABLED=1)
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address)
      target_compile_definitions(${target} PRIVATE NRP_ASAN_ENABLED=1)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(network_recovery_planner
  src/canonical.cpp
  src/codec.cpp
  src/crc32.cpp
  src/domain.cpp
  src/ids.cpp
  src/model.cpp
  src/objective.cpp
  src/persistence.cpp
  src/plan.cpp
  src/planner.cpp
  src/protocol.cpp
  src/reference_solver.cpp
  src/runtime_client.cpp
  src/runtime_server.cpp
  src/runtime_service.cpp
  src/validate.cpp
)
add_library(nrp::network_recovery_planner ALIAS network_recovery_planner)

target_include_directories(network_recovery_planner
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

nrp_apply_warnings(network_recovery_planner)
target_compile_features(network_recovery_planner PUBLIC cxx_std_20)

set_target_properties(network_recovery_planner PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME network_recovery_planner
  POSITION_INDEPENDENT_CODE ON)

if(WIN32)
  target_link_libraries(network_recovery_planner PRIVATE ws2_32)
endif()

# ---------------------------------------------------------------------------
# Tools, tests, examples
# ---------------------------------------------------------------------------
if(NRP_BUILD_TOOLS)
  add_executable(nrp-cli tools/nrp_cli.cpp)
  target_link_libraries(nrp-cli PRIVATE network_recovery_planner)
  set_target_properties(nrp-cli PROPERTIES OUTPUT_NAME nrp-cli)
  nrp_apply_warnings(nrp-cli)

  add_executable(nrp-server tools/nrp_server.cpp)
  target_link_libraries(nrp-server PRIVATE network_recovery_planner)
  set_target_properties(nrp-server PROPERTIES OUTPUT_NAME nrp-server)
  nrp_apply_warnings(nrp-server)
endif()

if(NRP_BUILD_EXAMPLES)
  add_executable(nrp_example_plan examples/plan_recovery.cpp)
  target_link_libraries(nrp_example_plan PRIVATE network_recovery_planner)
  nrp_apply_warnings(nrp_example_plan)
  add_executable(nrp_example_validate examples/validate_and_persist.cpp)
  target_link_libraries(nrp_example_validate PRIVATE network_recovery_planner)
  nrp_apply_warnings(nrp_example_validate)
endif()

if(NRP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install / package config
# ---------------------------------------------------------------------------
install(TARGETS network_recovery_planner
  EXPORT NetworkRecoveryPlannerTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(NRP_BUILD_TOOLS)
  install(TARGETS nrp-cli nrp-server
    EXPORT NetworkRecoveryPlannerTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/nrp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT NetworkRecoveryPlannerTargets
  FILE NetworkRecoveryPlannerTargets.cmake
  NAMESPACE nrp::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkRecoveryPlanner)

configure_package_config_file(
  cmake/NetworkRecoveryPlannerConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkRecoveryPlannerConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkRecoveryPlanner)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkRecoveryPlannerConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
  ARCH_INDEPENDENT)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkRecoveryPlannerConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/NetworkRecoveryPlannerConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkRecoveryPlanner)

install(FILES README.md LICENSE
  DESTINATION ${CMAKE_INSTALL_DOCDIR})
