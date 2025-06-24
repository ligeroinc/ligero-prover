(module
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))

  (func $test
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 0))) (call $i64_private_const (i64.const 1)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const 0)) (call $i64_private_const (i64.const 1))) (call $i64_private_const (i64.const 1)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 1))) (call $i64_private_const (i64.const 0)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const 0)) (call $i64_private_const (i64.const 0))) (call $i64_private_const (i64.const 0)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const 0x7fffffffffffffff)) (call $i64_private_const (i64.const 0x8000000000000000))) (call $i64_private_const (i64.const -1)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const 0x8000000000000000)) (call $i64_private_const (i64.const 0))) (call $i64_private_const (i64.const 0x8000000000000000)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const -1)) (call $i64_private_const (i64.const 0x8000000000000000))) (call $i64_private_const (i64.const 0x7fffffffffffffff)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const -1)) (call $i64_private_const (i64.const 0x7fffffffffffffff))) (call $i64_private_const (i64.const 0x8000000000000000)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const 0xf0f0ffff)) (call $i64_private_const (i64.const 0xfffff0f0))) (call $i64_private_const (i64.const 0x0f0f0f0f)))
    (call $assert_equal (i64.xor (call $i64_private_const (i64.const -1)) (call $i64_private_const (i64.const -1))) (call $i64_private_const (i64.const 0)))
  )

  (export "_start" (func $test))
)
