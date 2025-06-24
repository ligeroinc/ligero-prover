(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "assert_equal" (func $assert_equal (param i32 i32)))

(func $test
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 0)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 0)) (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 0x7fffffff)) (call $i32_private_const (i32.const 0x80000000))) (call $i32_private_const (i32.const -1)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 0x80000000)) (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 0x80000000)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const -1)) (call $i32_private_const (i32.const 0x80000000))) (call $i32_private_const (i32.const 0x7fffffff)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const -1)) (call $i32_private_const (i32.const 0x7fffffff))) (call $i32_private_const (i32.const 0x80000000)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 0xf0f0ffff)) (call $i32_private_const (i32.const 0xfffff0f0))) (call $i32_private_const (i32.const 0x0f0f0f0f)))
(call $assert_equal (i32.xor (call $i32_private_const (i32.const 0xffffffff)) (call $i32_private_const (i32.const 0xffffffff))) (call $i32_private_const (i32.const 0)))
)

(export "_start" (func $test)))