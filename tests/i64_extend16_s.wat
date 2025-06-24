(module
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))

  (func $test
    (call $assert_equal (i64.extend16_s (call $i64_private_const (i64.const 0))) (call $i64_private_const (i64.const 0)))
    (call $assert_equal (i64.extend16_s (call $i64_private_const (i64.const 0x7fff))) (call $i64_private_const (i64.const 32767)))
    (call $assert_equal (i64.extend16_s (call $i64_private_const (i64.const 0x8000))) (call $i64_private_const (i64.const -32768)))
    (call $assert_equal (i64.extend16_s (call $i64_private_const (i64.const 0xffff))) (call $i64_private_const (i64.const -1)))
    (call $assert_equal (i64.extend16_s (call $i64_private_const (i64.const 0x123456789abc0000))) (call $i64_private_const (i64.const 0)))
    (call $assert_equal (i64.extend16_s (call $i64_private_const (i64.const 0xfedcba9876548000))) (call $i64_private_const (i64.const -32768)))
    (call $assert_equal (i64.extend16_s (call $i64_private_const (i64.const -1))) (call $i64_private_const (i64.const -1)))
  )

  (export "_start" (func $test))
)
