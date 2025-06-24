(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))
  (import "env" "assert_equal_i32" (func $assert_equal_i32 (param i32 i32)))

  (func $test
    ;; i64.extend_i32_u tests
    (call $assert_equal (i64.extend_i32_u (call $i32_private_const (i32.const 0))) (i64.const 0))
    (call $assert_equal (i64.extend_i32_u (call $i32_private_const (i32.const 10000))) (i64.const 10000))
    (call $assert_equal (i64.extend_i32_u (call $i32_private_const (i32.const -10000))) (i64.const 0x00000000ffffd8f0))
    (call $assert_equal (i64.extend_i32_u (call $i32_private_const (i32.const -1))) (i64.const 0xffffffff))
    (call $assert_equal (i64.extend_i32_u (call $i32_private_const (i32.const 0x7fffffff))) (i64.const 0x000000007fffffff))
    (call $assert_equal (i64.extend_i32_u (call $i32_private_const (i32.const 0x80000000))) (i64.const 0x0000000080000000))
  )

  (export "_start" (func $test))
)
