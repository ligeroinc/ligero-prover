(module
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))

  (func $test
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const -1))) (call $i64_private_const (i64.const 64)))
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const 0))) (call $i64_private_const (i64.const 0)))
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const 0x00008000))) (call $i64_private_const (i64.const 1)))
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const 0x8000800080008000))) (call $i64_private_const (i64.const 4)))
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const 0x7fffffffffffffff))) (call $i64_private_const (i64.const 63)))
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const 0xAAAAAAAA55555555))) (call $i64_private_const (i64.const 32)))
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const 0x99999999AAAAAAAA))) (call $i64_private_const (i64.const 32)))
    (call $assert_equal (i64.popcnt (call $i64_private_const (i64.const 0xDEADBEEFDEADBEEF))) (call $i64_private_const (i64.const 48)))
  )

  (export "_start" (func $test))
)
