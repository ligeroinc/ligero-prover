;; Adapted from WebAssembly/testsuite f64.wast + conversions.wast
(module
  (memory 1)

  (func $assert_i32 (param $actual i32) (param $expected i32)
    local.get $actual
    local.get $expected
    i32.ne
    if
      unreachable
    end)

  (func $assert_i64 (param $actual i64) (param $expected i64)
    local.get $actual
    local.get $expected
    i64.ne
    if
      unreachable
    end)

  (func $assert_f64 (param $actual f64) (param $expected f64)
    local.get $actual
    local.get $expected
    f64.eq
    i32.eqz
    if
      unreachable
    end)

  (func $assert_f64_nan (param $value f64)
    local.get $value
    local.get $value
    f64.ne
    i32.eqz
    if
      unreachable
    end)

  (func $_start
    ;; const / unary
    (call $assert_f64 (f64.const 1.5) (f64.const 1.5))
    (call $assert_f64 (f64.abs (f64.const -13.5)) (f64.const 13.5))
    (call $assert_f64 (f64.neg (f64.const 3.5)) (f64.const -3.5))
    (call $assert_f64 (f64.ceil (f64.const 3.25)) (f64.const 4.0))
    (call $assert_f64 (f64.floor (f64.const 3.75)) (f64.const 3.0))
    (call $assert_f64 (f64.trunc (f64.const -3.75)) (f64.const -3.0))
    (call $assert_f64 (f64.nearest (f64.const 2.5)) (f64.const 2.0))
    (call $assert_f64 (f64.nearest (f64.const 3.5)) (f64.const 4.0))
    (call $assert_f64 (f64.sqrt (f64.const 9.0)) (f64.const 3.0))

    ;; binary
    (call $assert_f64 (f64.add (f64.const 1.25) (f64.const 2.75)) (f64.const 4.0))
    (call $assert_f64 (f64.sub (f64.const 10.0) (f64.const 3.5)) (f64.const 6.5))
    (call $assert_f64 (f64.mul (f64.const 1.5) (f64.const 4.0)) (f64.const 6.0))
    (call $assert_f64 (f64.div (f64.const 7.0) (f64.const 2.0)) (f64.const 3.5))
    (call $assert_f64 (f64.min (f64.const 1.0) (f64.const 4.0)) (f64.const 1.0))
    (call $assert_f64 (f64.max (f64.const 1.0) (f64.const 4.0)) (f64.const 4.0))
    (call $assert_f64 (f64.copysign (f64.const 3.0) (f64.const -1.0)) (f64.const -3.0))

    ;; comparisons
    (call $assert_i32 (f64.eq (f64.const 2.0) (f64.const 2.0)) (i32.const 1))
    (call $assert_i32 (f64.ne (f64.const 2.0) (f64.const 3.0)) (i32.const 1))
    (call $assert_i32 (f64.lt (f64.const 2.0) (f64.const 3.0)) (i32.const 1))
    (call $assert_i32 (f64.gt (f64.const 3.0) (f64.const 2.0)) (i32.const 1))
    (call $assert_i32 (f64.le (f64.const 3.0) (f64.const 3.0)) (i32.const 1))
    (call $assert_i32 (f64.ge (f64.const 3.0) (f64.const 3.0)) (i32.const 1))

    ;; nan behavior
    (call $assert_i32 (f64.eq (f64.const nan) (f64.const 0.0)) (i32.const 0))
    (call $assert_i32 (f64.ne (f64.const nan) (f64.const 0.0)) (i32.const 1))
    (call $assert_f64_nan (f64.div (f64.const 0.0) (f64.const 0.0)))

    ;; conversions into f64
    (call $assert_f64 (f64.convert_i32_s (i32.const -1234)) (f64.const -1234.0))
    (call $assert_f64 (f64.convert_i32_u (i32.const 1234)) (f64.const 1234.0))
    (call $assert_f64 (f64.convert_i64_s (i64.const -123456)) (f64.const -123456.0))
    (call $assert_f64 (f64.convert_i64_u (i64.const 123456)) (f64.const 123456.0))
    (call $assert_f64 (f64.promote_f32 (f32.const 6.25)) (f64.const 6.25))

    ;; reinterpret
    (call $assert_i64 (i64.reinterpret_f64 (f64.const 1.0)) (i64.const 0x3ff0000000000000))
    (call $assert_f64 (f64.reinterpret_i64 (i64.const 0x4000000000000000)) (f64.const 2.0))

    ;; trunc (non-saturating)
    (call $assert_i32 (i32.trunc_f64_s (f64.const -1.9)) (i32.const -1))
    (call $assert_i32 (i32.trunc_f64_u (f64.const 10.9)) (i32.const 10))
    (call $assert_i64 (i64.trunc_f64_s (f64.const -12345.75)) (i64.const -12345))
    (call $assert_i64 (i64.trunc_f64_u (f64.const 12345.75)) (i64.const 12345))

    ;; trunc_sat
    (call $assert_i32 (i32.trunc_sat_f64_s (f64.const nan)) (i32.const 0))
    (call $assert_i32 (i32.trunc_sat_f64_s (f64.const 1e300)) (i32.const 2147483647))
    (call $assert_i32 (i32.trunc_sat_f64_s (f64.const -1e300)) (i32.const -2147483648))
    (call $assert_i32 (i32.trunc_sat_f64_u (f64.const -10.0)) (i32.const 0))
    (call $assert_i32 (i32.trunc_sat_f64_u (f64.const 1e300)) (i32.const -1))

    (call $assert_i64 (i64.trunc_sat_f64_s (f64.const nan)) (i64.const 0))
    (call $assert_i64 (i64.trunc_sat_f64_s (f64.const 1e300)) (i64.const 9223372036854775807))
    (call $assert_i64 (i64.trunc_sat_f64_s (f64.const -1e300)) (i64.const -9223372036854775808))
    (call $assert_i64 (i64.trunc_sat_f64_u (f64.const -10.0)) (i64.const 0))
    (call $assert_i64 (i64.trunc_sat_f64_u (f64.const 1e300)) (i64.const -1))

    ;; memory load/store
    (f64.store (i32.const 0) (f64.const 3.5))
    (call $assert_f64 (f64.load (i32.const 0)) (f64.const 3.5))

    (f64.store offset=8 (i32.const 0) (f64.const -2.25))
    (call $assert_f64 (f64.load offset=8 (i32.const 0)) (f64.const -2.25))
  )

  (export "_start" (func $_start))
)
