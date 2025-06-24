(module
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))

  (func $test
    (call $assert_equal (i64.extend8_s (call $i64_private_const (i64.const 0))) (call $i64_private_const (i64.const 0)))
    (call $assert_equal (i64.extend8_s (call $i64_private_const (i64.const 0x7f))) (call $i64_private_const (i64.const 127)))
    (call $assert_equal (i64.extend8_s (call $i64_private_const (i64.const 0x80))) (call $i64_private_const (i64.const -128)))
    (call $assert_equal (i64.extend8_s (call $i64_private_const (i64.const 0xff))) (call $i64_private_const (i64.const -1)))
    (call $assert_equal (i64.extend8_s (call $i64_private_const (i64.const 0x0123456789abcd00))) (call $i64_private_const (i64.const 0)))
    (call $assert_equal (i64.extend8_s (call $i64_private_const (i64.const 0xfedcba9876543280))) (call $i64_private_const (i64.const -128)))
    (call $assert_equal (i64.extend8_s (call $i64_private_const (i64.const -1))) (call $i64_private_const (i64.const -1)))
  )

  (export "_start" (func $test))
)
