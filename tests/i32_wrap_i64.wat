(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))
  (import "env" "assert_equal_i32" (func $assert_equal_i32 (param i32 i32)))

  (func $test
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const -1))) (call $i32_private_const (i32.const -1)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const -100000))) (call $i32_private_const (i32.const -100000)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0x80000000))) (call $i32_private_const (i32.const 0x80000000)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0xffffffff7fffffff))) (call $i32_private_const (i32.const 0x7fffffff)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0xffffffff00000000))) (call $i32_private_const (i32.const 0x00000000)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0xfffffffeffffffff))) (call $i32_private_const (i32.const 0xffffffff)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0xffffffff00000001))) (call $i32_private_const (i32.const 0x00000001)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0))) (call $i32_private_const (i32.const 0)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 1311768467463790320))) (call $i32_private_const (i32.const 0x9abcdef0)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0x00000000ffffffff))) (call $i32_private_const (i32.const 0xffffffff)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0x0000000100000000))) (call $i32_private_const (i32.const 0x00000000)))
  (call $assert_equal (i32.wrap_i64 (call $i64_private_const (i64.const 0x0000000100000001))) (call $i32_private_const (i32.const 0x00000001)))
  )

  (export "_start" (func $test))
)
