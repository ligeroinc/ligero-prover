(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "assert_equal" (func $assert_equal (param i32 i32)))

(func $test
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 0)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const -1)) (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 0x80000000)) (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 0x80000000)) (call $i32_private_const (i32.const 2))) (call $i32_private_const (i32.const 0x40000000)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 0x8ff00ff0)) (call $i32_private_const (i32.const 0x10001))) (call $i32_private_const (i32.const 0x8fef)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 0x80000001)) (call $i32_private_const (i32.const 1000))) (call $i32_private_const (i32.const 0x20c49b)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 5)) (call $i32_private_const (i32.const 2))) (call $i32_private_const (i32.const 2)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const -5)) (call $i32_private_const (i32.const 2))) (call $i32_private_const (i32.const 0x7ffffffd)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 5)) (call $i32_private_const (i32.const -2))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const -5)) (call $i32_private_const (i32.const -2))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 7)) (call $i32_private_const (i32.const 3))) (call $i32_private_const (i32.const 2)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 11)) (call $i32_private_const (i32.const 5))) (call $i32_private_const (i32.const 2)))
(call $assert_equal (i32.div_u (call $i32_private_const (i32.const 17)) (call $i32_private_const (i32.const 7))) (call $i32_private_const (i32.const 2)))
)

(export "_start" (func $test)))