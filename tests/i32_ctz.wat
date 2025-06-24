(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "assert_equal" (func $assert_equal (param i32 i32)))

(func $test
(call $assert_equal (i32.ctz (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.ctz (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 32)))
(call $assert_equal (i32.ctz (call $i32_private_const (i32.const 0x00008000))) (call $i32_private_const (i32.const 15)))
(call $assert_equal (i32.ctz (call $i32_private_const (i32.const 0x00010000))) (call $i32_private_const (i32.const 16)))
(call $assert_equal (i32.ctz (call $i32_private_const (i32.const 0x80000000))) (call $i32_private_const (i32.const 31)))
(call $assert_equal (i32.ctz (call $i32_private_const (i32.const 0x7fffffff))) (call $i32_private_const (i32.const 0)))
)

(export "_start" (func $test)))