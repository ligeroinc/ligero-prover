(module
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))

  (func $test
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0)) (call $i64_private_const (i64.const 0))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 1))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const -1)) (call $i64_private_const (i64.const 1))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0x8000000000000000)) (call $i64_private_const (i64.const 0x8000000000000000))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0x7fffffffffffffff)) (call $i64_private_const (i64.const 0x7fffffffffffffff))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const -1)) (call $i64_private_const (i64.const -1))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 0))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0)) (call $i64_private_const (i64.const 1))) (i32.const 0))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0x8000000000000000)) (call $i64_private_const (i64.const 0))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0)) (call $i64_private_const (i64.const 0x8000000000000000))) (i32.const 0))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0x8000000000000000)) (call $i64_private_const (i64.const -1))) (i32.const 0))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const -1)) (call $i64_private_const (i64.const 0x8000000000000000))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0x8000000000000000)) (call $i64_private_const (i64.const 0x7fffffffffffffff))) (i32.const 1))
    (call $assert_equal (i64.ge_u (call $i64_private_const (i64.const 0x7fffffffffffffff)) (call $i64_private_const (i64.const 0x8000000000000000))) (i32.const 0))
  )

  (export "_start" (func $test))
)
