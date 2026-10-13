add_executable(test_vm_transfers test_value_transfer.cpp)
target_link_libraries(test_vm_transfers PRIVATE
  ecdsa_r1cs_dependencies bn254 nlohmann_json::nlohmann_json)
if(EMSCRIPTEN)
  target_link_libraries(test_vm_transfers PRIVATE wasm::wabt)
  set_target_properties(test_vm_transfers PROPERTIES SUFFIX ".js")
  # The ownership regression intentionally catches invalid frame accesses.
  target_compile_options(test_vm_transfers PRIVATE -fexceptions)
  target_link_options(test_vm_transfers PRIVATE -fexceptions -sINVOKE_RUN=1 -sENVIRONMENT=node
    -sEXIT_RUNTIME=1 -sSTACK_SIZE=1048576 -sALLOW_MEMORY_GROWTH=1)
  add_test(NAME vm.value_transfers COMMAND node $<TARGET_FILE:test_vm_transfers>)
else()
  target_link_libraries(test_vm_transfers PRIVATE wabt::wabt)
  # Context templates reference WebGPU types; this CPU-only test needs headers
  # but does not link or initialize the GPU runtime.
  target_include_directories(test_vm_transfers PRIVATE
    $<TARGET_PROPERTY:dawn::webgpu_dawn,INTERFACE_INCLUDE_DIRECTORIES>)
  add_test(NAME vm.value_transfers COMMAND test_vm_transfers)
endif()
set_tests_properties(vm.value_transfers PROPERTIES LABELS "unit;vm" TIMEOUT 60)
