# Network Recovery Planner - test suites.
# Copyright 2026 Summon Software Labs. Apache License 2.0.

add_library(nrp_test_support STATIC support/test_main.cpp support/process_helper.cpp)
target_link_libraries(nrp_test_support PUBLIC network_recovery_planner)
target_include_directories(nrp_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src)
nrp_apply_warnings(nrp_test_support)

# Tests must never be killed by a watchdog: a hanging test is a defect to be
# diagnosed, so no CTest timeout is set.
function(nrp_add_suite name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE nrp_test_support)
  nrp_apply_warnings(${name})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

nrp_add_suite(nrp_test_core test_core.cpp)
nrp_add_suite(nrp_test_model test_model.cpp)
nrp_add_suite(nrp_test_planner test_planner.cpp)
nrp_add_suite(nrp_test_validate test_validate.cpp)
nrp_add_suite(nrp_test_differential test_differential.cpp)
nrp_add_suite(nrp_test_adversarial test_adversarial.cpp)
nrp_add_suite(nrp_test_persistence test_persistence.cpp)
nrp_add_suite(nrp_test_protocol test_protocol.cpp)
nrp_add_suite(nrp_test_concurrency test_concurrency.cpp)
nrp_add_suite(nrp_test_scale test_scale.cpp)

if(NRP_BUILD_TOOLS)
  nrp_add_suite(nrp_test_multiprocess test_multiprocess.cpp)
  target_compile_definitions(nrp_test_multiprocess PRIVATE
    NRP_SERVER_EXE="$<TARGET_FILE:nrp-server>")
  add_dependencies(nrp_test_multiprocess nrp-server)
endif()
