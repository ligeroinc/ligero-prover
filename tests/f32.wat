;; Adapted from WebAssembly/testsuite f32.wast + conversions.wast
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

  (func $assert_f32 (param $actual f32) (param $expected f32)
    local.get $actual
    local.get $expected
    f32.eq
    i32.eqz
    if
      unreachable
    end)

  (func $assert_f32_nan (param $value f32)
    local.get $value
    local.get $value
    f32.ne
    i32.eqz
    if
      unreachable
    end)

  (func $_start
    ;; const / unary
    (call $assert_f32 (f32.const 1.5) (f32.const 1.5))
    (call $assert_f32 (f32.abs (f32.const -13.5)) (f32.const 13.5))
    (call $assert_f32 (f32.neg (f32.const 3.5)) (f32.const -3.5))
    (call $assert_f32 (f32.ceil (f32.const 3.25)) (f32.const 4.0))
    (call $assert_f32 (f32.floor (f32.const 3.75)) (f32.const 3.0))
    (call $assert_f32 (f32.trunc (f32.const -3.75)) (f32.const -3.0))
    (call $assert_f32 (f32.nearest (f32.const 2.5)) (f32.const 2.0))
    (call $assert_f32 (f32.nearest (f32.const 3.5)) (f32.const 4.0))
    (call $assert_f32 (f32.sqrt (f32.const 9.0)) (f32.const 3.0))

    ;; binary
    (call $assert_f32 (f32.add (f32.const 1.25) (f32.const 2.75)) (f32.const 4.0))
    (call $assert_f32 (f32.sub (f32.const 10.0) (f32.const 3.5)) (f32.const 6.5))
    (call $assert_f32 (f32.mul (f32.const 1.5) (f32.const 4.0)) (f32.const 6.0))
    (call $assert_f32 (f32.div (f32.const 7.0) (f32.const 2.0)) (f32.const 3.5))
    (call $assert_f32 (f32.min (f32.const 1.0) (f32.const 4.0)) (f32.const 1.0))
    (call $assert_f32 (f32.max (f32.const 1.0) (f32.const 4.0)) (f32.const 4.0))
    (call $assert_f32 (f32.copysign (f32.const 3.0) (f32.const -1.0)) (f32.const -3.0))

    ;; comparisons
    (call $assert_i32 (f32.eq (f32.const 2.0) (f32.const 2.0)) (i32.const 1))
    (call $assert_i32 (f32.ne (f32.const 2.0) (f32.const 3.0)) (i32.const 1))
    (call $assert_i32 (f32.lt (f32.const 2.0) (f32.const 3.0)) (i32.const 1))
    (call $assert_i32 (f32.gt (f32.const 3.0) (f32.const 2.0)) (i32.const 1))
    (call $assert_i32 (f32.le (f32.const 3.0) (f32.const 3.0)) (i32.const 1))
    (call $assert_i32 (f32.ge (f32.const 3.0) (f32.const 3.0)) (i32.const 1))

    ;; nan behavior
    (call $assert_i32 (f32.eq (f32.const nan) (f32.const 0.0)) (i32.const 0))
    (call $assert_i32 (f32.ne (f32.const nan) (f32.const 0.0)) (i32.const 1))
    (call $assert_f32_nan (f32.div (f32.const 0.0) (f32.const 0.0)))

    ;; conversions into f32
    (call $assert_f32 (f32.convert_i32_s (i32.const -1234)) (f32.const -1234.0))
    (call $assert_f32 (f32.convert_i32_u (i32.const 1234)) (f32.const 1234.0))
    (call $assert_f32 (f32.convert_i64_s (i64.const -123456)) (f32.const -123456.0))
    (call $assert_f32 (f32.convert_i64_u (i64.const 123456)) (f32.const 123456.0))
    (call $assert_f32 (f32.demote_f64 (f64.const 6.25)) (f32.const 6.25))

    ;; reinterpret
    (call $assert_i32 (i32.reinterpret_f32 (f32.const 1.0)) (i32.const 0x3f800000))
    (call $assert_f32 (f32.reinterpret_i32 (i32.const 0x40000000)) (f32.const 2.0))

    ;; trunc (non-saturating)
    (call $assert_i32 (i32.trunc_f32_s (f32.const -1.9)) (i32.const -1))
    (call $assert_i32 (i32.trunc_f32_u (f32.const 10.9)) (i32.const 10))
    (call $assert_i64 (i64.trunc_f32_s (f32.const -12345.75)) (i64.const -12345))
    (call $assert_i64 (i64.trunc_f32_u (f32.const 12345.75)) (i64.const 12345))

    ;; trunc_sat
    (call $assert_i32 (i32.trunc_sat_f32_s (f32.const nan)) (i32.const 0))
    (call $assert_i32 (i32.trunc_sat_f32_s (f32.const 1e30)) (i32.const 2147483647))
    (call $assert_i32 (i32.trunc_sat_f32_s (f32.const -1e30)) (i32.const -2147483648))
    (call $assert_i32 (i32.trunc_sat_f32_u (f32.const -10.0)) (i32.const 0))
    (call $assert_i32 (i32.trunc_sat_f32_u (f32.const 1e30)) (i32.const -1))

    (call $assert_i64 (i64.trunc_sat_f32_s (f32.const nan)) (i64.const 0))
    (call $assert_i64 (i64.trunc_sat_f32_s (f32.const 1e30)) (i64.const 9223372036854775807))
    (call $assert_i64 (i64.trunc_sat_f32_s (f32.const -1e30)) (i64.const -9223372036854775808))
    (call $assert_i64 (i64.trunc_sat_f32_u (f32.const -10.0)) (i64.const 0))
    (call $assert_i64 (i64.trunc_sat_f32_u (f32.const 1e30)) (i64.const -1))

    ;; memory load/store
    (f32.store (i32.const 0) (f32.const 3.5))
    (call $assert_f32 (f32.load (i32.const 0)) (f32.const 3.5))

    (f32.store offset=4 (i32.const 0) (f32.const -2.25))
    (call $assert_f32 (f32.load offset=4 (i32.const 0)) (f32.const -2.25))
  )

  (export "_start" (func $_start))
)
