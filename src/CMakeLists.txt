include_directories(.)

add_executable(
  test_cmp

  test_cmp.cpp
)
target_link_libraries(
  test_cmp

  snark
)
target_include_directories(
  test_cmp

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
