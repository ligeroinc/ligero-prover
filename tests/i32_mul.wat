(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "assert_equal" (func $assert_equal (param i32 i32)))

(func $test
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const -1)) (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 0x10000000)) (call $i32_private_const (i32.const 4096))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 0x80000000)) (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 0x80000000)) (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const 0x80000000)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 0x7fffffff)) (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const 0x80000001)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 0x01234567)) (call $i32_private_const (i32.const 0x76543210))) (call $i32_private_const (i32.const 0x358e7470)))
(call $assert_equal (i32.mul (call $i32_private_const (i32.const 0x7fffffff)) (call $i32_private_const (i32.const 0x7fffffff))) (call $i32_private_const (i32.const 1)))
)

(export "_start" (func $test)))