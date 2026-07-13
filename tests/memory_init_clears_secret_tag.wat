(module
  (import "env" "i32_private_const" (func $i32_private_const (param i32) (result i32)))
  (import "env" "assert_is_concrete" (func $assert_is_concrete (param i32)))
  (memory 1)
  (data $zeros "\00\00\00\00")

  (func $test
    ;; 1. Store a witness value to address 0.
    (i32.store (i32.const 0) (call $i32_private_const (i32.const 0x42)))
    ;; 2. Overwrite with static data segment bytes via memory.init.
    (memory.init $zeros (i32.const 0) (i32.const 0) (i32.const 4))
    ;; 3. Load and assert the result is concrete (not a witness).
    ;;    Correct behaviour: load returns concrete 0, assert succeeds.
    ;;    With bug:          load returns a witness, assert traps.
    (call $assert_is_concrete (i32.load (i32.const 0)))
  )

  (export "_start" (func $test))
)
