(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "assert_equal" (func $assert_equal (param i32 i32)))

(func $test
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 2)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 0))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const -1)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const -1)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 32))) (call $i32_private_const (i32.const 1)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0xabcd9876)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 0x579b30ed)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0xfe00dc00)) (call $i32_private_const (i32.const 4))) (call $i32_private_const (i32.const 0xe00dc00f)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0xb0c1d2e3)) (call $i32_private_const (i32.const 5))) (call $i32_private_const (i32.const 0x183a5c76)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0x00008000)) (call $i32_private_const (i32.const 37))) (call $i32_private_const (i32.const 0x00100000)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0xb0c1d2e3)) (call $i32_private_const (i32.const 0xff05))) (call $i32_private_const (i32.const 0x183a5c76)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0x769abcdf)) (call $i32_private_const (i32.const 0xffffffed))) (call $i32_private_const (i32.const 0x579beed3)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0x769abcdf)) (call $i32_private_const (i32.const 0x8000000d))) (call $i32_private_const (i32.const 0x579beed3)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 1)) (call $i32_private_const (i32.const 31))) (call $i32_private_const (i32.const 0x80000000)))
(call $assert_equal (i32.rotl (call $i32_private_const (i32.const 0x80000000)) (call $i32_private_const (i32.const 1))) (call $i32_private_const (i32.const 1)))
)

(export "_start" (func $test)))