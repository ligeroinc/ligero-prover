(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "assert_equal" (func $assert_equal (param i32 i32)))

(func $test
(call $assert_equal (i32.extend8_s (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.extend8_s (call $i32_private_const (i32.const 0x7f))) (call $i32_private_const (i32.const 127)))
(call $assert_equal (i32.extend8_s (call $i32_private_const (i32.const 0x80))) (call $i32_private_const (i32.const -128)))
(call $assert_equal (i32.extend8_s (call $i32_private_const (i32.const 0xff))) (call $i32_private_const (i32.const -1)))
(call $assert_equal (i32.extend8_s (call $i32_private_const (i32.const 0x012345_00))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.extend8_s (call $i32_private_const (i32.const 0xfedcba_80))) (call $i32_private_const (i32.const -0x80)))
(call $assert_equal (i32.extend8_s (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const -1)))

(call $assert_equal (i32.extend16_s (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.extend16_s (call $i32_private_const (i32.const 0x7fff))) (call $i32_private_const (i32.const 32767)))
(call $assert_equal (i32.extend16_s (call $i32_private_const (i32.const 0x8000))) (call $i32_private_const (i32.const -32768)))
(call $assert_equal (i32.extend16_s (call $i32_private_const (i32.const 0xffff))) (call $i32_private_const (i32.const -1)))
(call $assert_equal (i32.extend16_s (call $i32_private_const (i32.const 0x0123_0000))) (call $i32_private_const (i32.const 0)))
(call $assert_equal (i32.extend16_s (call $i32_private_const (i32.const 0xfedc_8000))) (call $i32_private_const (i32.const -0x8000)))
(call $assert_equal (i32.extend16_s (call $i32_private_const (i32.const -1))) (call $i32_private_const (i32.const -1)))
)

(export "_start" (func $test)))