(module
  (import "env" "i64_private_const" (func $i64_private_const (param i64) (result i64)))
  (import "env" "assert_equal" (func $assert_equal (param i64 i64)))

  (func $test
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 1))) (call $i64_private_const (i64.const 2)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 0))) (call $i64_private_const (i64.const 1)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const -1)) (call $i64_private_const (i64.const 1))) (call $i64_private_const (i64.const -1)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 64))) (call $i64_private_const (i64.const 1)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0xabcd987602468ace)) (call $i64_private_const (i64.const 1))) (call $i64_private_const (i64.const 0x579b30ec048d159d)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0xfe000000dc000000)) (call $i64_private_const (i64.const 4))) (call $i64_private_const (i64.const 0xe000000dc000000f)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0xabcd1234ef567809)) (call $i64_private_const (i64.const 53))) (call $i64_private_const (i64.const 0x013579a2469deacf)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0xabd1234ef567809c)) (call $i64_private_const (i64.const 63))) (call $i64_private_const (i64.const 0x55e891a77ab3c04e)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0xabcd1234ef567809)) (call $i64_private_const (i64.const 0xf5))) (call $i64_private_const (i64.const 0x013579a2469deacf)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0xabcd7294ef567809)) (call $i64_private_const (i64.const 0xffffffffffffffed))) (call $i64_private_const (i64.const 0xcf013579ae529dea)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0xabd1234ef567809c)) (call $i64_private_const (i64.const 0x800000000000003f))) (call $i64_private_const (i64.const 0x55e891a77ab3c04e)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 1)) (call $i64_private_const (i64.const 63))) (call $i64_private_const (i64.const 0x8000000000000000)))
    (call $assert_equal (i64.rotl (call $i64_private_const (i64.const 0x8000000000000000)) (call $i64_private_const (i64.const 1))) (call $i64_private_const (i64.const 1)))
  )

  (export "_start" (func $test))
)
