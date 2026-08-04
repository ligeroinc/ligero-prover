#!/usr/bin/env bash
#
# Runs the wasm test programs under the Ligetron VM.
#
# Build them first -- TWO passes, into SEPARATE target dirs:
#     cargo build --target wasm32-wasip1 --release --features vm-tests --bins
#     cargo build --target wasm32-wasip1 --release --features vm-tests,fault-injection --bins \
#         --target-dir target/fault-injection
#
# The split is not tidiness. Enabling `fault-injection` changes lib codegen and therefore the
# constraint counts -- measured: ed25519_test is 2,987,746/5,699,206 without it and
# 2,987,737/5,699,047 with it. Positive suites must be built WITHOUT it so their pinned counts
# describe the circuit that actually ships; negative suites need it. One target dir cannot hold
# both, since the two passes emit the same bin names.
#
# Then, from sdk/rust:
#     tests_wasm/run.sh                  # every suite
#     tests_wasm/run.sh bn254fr_test     # just these
#
# Each suite must prove true AND emit the constraint counts recorded in
# expected_constraints.txt. The counts are a property of the circuit, not of the
# run -- they are deterministic and independent of `packing` -- so any movement is
# a semantic change, and the diff of that file is the record of it. After a change
# you believe should move them:
#
#     UPDATE_COUNTS=1 tests_wasm/run.sh
#
# and review the resulting diff as part of the change.
#
# Override the prover location with LIGETRON_BUILD if it is not at the repo default.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="${LIGETRON_BUILD:-$HERE/../../../build}"
WASM="$HERE/../target/wasm32-wasip1/release"
# Negative suites come from the fault-injection build; see the note above on why it is separate.
WASM_FI="$HERE/../target/fault-injection/wasm32-wasip1/release"
EXPECTED="$HERE/expected_constraints.txt"
UPDATE_COUNTS="${UPDATE_COUNTS:-0}"

ALL_SUITES=(sha256_test sha512_test bn254fr_test bn254fr_bigint_test uint256_test prime_field_test
            p256_test ecdsa_p256_test ed25519_test ed25519_eddsa_test
            negative_on_curve_test negative_scalar_binding_test
            negative_msm_identity_test negative_sign_boolean_test
            negative_magnitude_nonzero_test
            negative_div_multiply_back_test
            negative_div_non_unique_test
            negative_uint256_invmod_test
            negative_bigint_idiv_test
            negative_bigint_rem_test
            negative_bigint_invmod_test
            negative_get_u64_high_limbs_test
            negative_set_words_binding_test
            negative_from_bits_binding_test
            negative_bigint_idiv_non_unique_test
            negative_bigint_rem_non_unique_test
            negative_bigint_from_limbs_binding_test
            negative_bigint_set_binding_test
            negative_bigint_add_surplus_test
            negative_bigint_sub_surplus_test
            negative_bigint_lt_binding_test
            negative_bigint_add_carry_binding_test
            negative_bigint_proper_top_test
            negative_bigint_signed_copy_test
            negative_ff_import_u64_test
            negative_ff_import_u32_test
            negative_ff_zero_mod_test
            negative_div_b_pad_test
            negative_bigint_invmod_rest_test)

# Suites that MUST NOT prove. Every other suite feeds valid values and so only shows that the
# constraint system accepts a correct witness; these feed an invalid one and show that it
# rejects. For them `Final prove result: false` is the pass and `true` is the failure -- if one
# starts proving, the assertion it targets has stopped binding.
#
# Keep each to a single constrained call. A program that trips two assertions still fails, so
# it would keep passing after one of them was removed, and the suite would be attributing a
# failure to the wrong line.
NEGATIVE_SUITES=(negative_on_curve_test negative_scalar_binding_test
                 negative_msm_identity_test negative_sign_boolean_test
                 negative_magnitude_nonzero_test
            negative_div_multiply_back_test
            negative_div_non_unique_test
            negative_uint256_invmod_test
            negative_bigint_idiv_test
            negative_bigint_rem_test
            negative_bigint_invmod_test
            negative_get_u64_high_limbs_test
            negative_set_words_binding_test
            negative_from_bits_binding_test
            negative_bigint_idiv_non_unique_test
            negative_bigint_rem_non_unique_test
            negative_bigint_from_limbs_binding_test
            negative_bigint_set_binding_test
            negative_bigint_add_surplus_test
            negative_bigint_sub_surplus_test
            negative_bigint_lt_binding_test
            negative_bigint_add_carry_binding_test
            negative_bigint_proper_top_test
            negative_bigint_signed_copy_test
            negative_ff_import_u64_test
            negative_ff_import_u32_test
            negative_ff_zero_mod_test
            negative_div_b_pad_test
            negative_bigint_invmod_rest_test)

is_negative() {
    local s
    for s in "${NEGATIVE_SUITES[@]}"; do
        [[ "$1" == "$s" ]] && return 0
    done
    return 1
}

# Named suites only, if any were given. Unrun suites keep their recorded counts,
# so `UPDATE_COUNTS=1 tests_wasm/run.sh <one>` rebaselines just that one.
if [[ $# -gt 0 ]]; then
    for want in "$@"; do
        found=0
        for known in "${ALL_SUITES[@]}"; do
            [[ "$want" == "$known" ]] && found=1
        done
        if [[ "$found" != 1 ]]; then
            echo "unknown suite: $want" >&2
            printf 'known suites: %s\n' "${ALL_SUITES[*]}" >&2
            exit 2
        fi
    done
    SUITES=("$@")
else
    SUITES=("${ALL_SUITES[@]}")
fi

if [[ ! -x "$BUILD/webgpu_prover" ]]; then
    echo "webgpu_prover not found at $BUILD; set LIGETRON_BUILD" >&2
    exit 1
fi

if [[ ! -f "$EXPECTED" && "$UPDATE_COUNTS" != 1 ]]; then
    echo "no baseline at $EXPECTED; create it with UPDATE_COUNTS=1 $0" >&2
    exit 1
fi

# Deliberately no associative arrays: macOS ships bash 3.2, which lacks them.
# "<linear> <quadratic>" for a suite in the baseline file, or "" if unrecorded.
recorded_for() {
    [[ -f "$EXPECTED" ]] || return 0
    awk -v s="$1" '$1 == s { print $2, $3 }' "$EXPECTED"
}

# Last field of the first matching line, or "" if absent. The prover reports the
# quadratic count once per stage; the stages agree, so the first is enough.
field_of() { grep -im1 "$2" "$1" | awk '{print $NF}' || true; }

log="$(mktemp)"
fresh="$(mktemp)"          # "<suite> <linear> <quadratic>" measured in this run
rewritten="$(mktemp)"      # staging for the new baseline; see the mv below
trap 'rm -f "$log" "$fresh" "$rewritten"' EXIT

declare -a report=()
failed=0

for t in "${SUITES[@]}"; do
    if is_negative "$t"; then dir="$WASM_FI"; else dir="$WASM"; fi
    if [[ ! -f "$dir/$t.wasm" ]]; then
        # A missing NEGATIVE suite is a failure, not a skip: they need the extra
        # `fault-injection` feature, so forgetting it would silently drop every soundness
        # check while the run still reported green.
        if is_negative "$t"; then
            echo "MISSING $t -- build with --features vm-tests,fault-injection --target-dir target/fault-injection" >&2
            report+=("$t NOT-BUILT - -")
            failed=1
        else
            echo "SKIP $t (not built)" >&2
            report+=("$t SKIP - -")
        fi
        continue
    fi
    echo "=== $t ==="
    # `|| prover_rc=$?` is required, not defensive: the prover exits nonzero when a proof
    # fails, and under `set -euo pipefail` that would kill this script before the summary --
    # which is exactly what a NEGATIVE suite does on a good day.
    prover_rc=0
    ( cd "$BUILD" && ./webgpu_prover \
        "{\"program\":\"$dir/$t.wasm\",\"shader-path\":\"./shader\",\"packing\":8192}" ) \
        | tee "$log" || prover_rc=$?

    result="$(field_of "$log" 'Final prove result:')"

    # No verdict line at all means the prover died rather than reported -- distinct from
    # either a failed proof or an unexpected pass, and mislabelled as both without this.
    if [[ -z "$result" ]]; then
        report+=("$t NO-RESULT(rc=$prover_rc) - -")
        failed=1
        continue
    fi
    lin="$(field_of "$log" 'Num Linear constraints:')"
    quad="$(field_of "$log" 'Num quadratic constraints:')"

    if is_negative "$t"; then
        # Inverted: this suite passes by failing to prove.
        if [[ "$result" != "false" ]]; then
            report+=("$t PROVED-ANYWAY ${lin:--} ${quad:--}")
            failed=1
            continue
        fi
    elif [[ "$result" != "true" ]]; then
        report+=("$t PROOF-FAILED ${lin:--} ${quad:--}")
        failed=1
        continue
    fi
    if [[ -z "$lin" || -z "$quad" ]]; then
        report+=("$t NO-COUNTS - -")
        failed=1
        continue
    fi

    if [[ "$UPDATE_COUNTS" == 1 ]]; then
        echo "$t $lin $quad" >> "$fresh"
        report+=("$t recorded $lin $quad")
        continue
    fi

    want="$(recorded_for "$t")"
    if [[ -z "$want" ]]; then
        report+=("$t UNRECORDED $lin $quad")
        failed=1
    elif [[ "$want" != "$lin $quad" ]]; then
        report+=("$t DRIFT $lin $quad expected:$(tr ' ' '/' <<<"$want")")
        failed=1
    else
        report+=("$t ok $lin $quad")
    fi
done

if [[ "$UPDATE_COUNTS" == 1 ]]; then
    {
        echo "# Constraint counts per vm-test suite: <suite> <linear> <quadratic>."
        echo "#"
        echo "# Regenerate with:  UPDATE_COUNTS=1 tests_wasm/run.sh"
        echo "# A diff here is a semantic change to the circuit -- review it, don't just take it."
        # This run's measurement wins; anything skipped keeps its recorded value,
        # so a partial build cannot silently erase the baseline.
        for t in "${ALL_SUITES[@]}"; do
            v="$(awk -v s="$t" '$1 == s { print $2, $3 }' "$fresh")"
            [[ -z "$v" ]] && v="$(recorded_for "$t")"
            [[ -n "$v" ]] && printf "%-32s %s\n" "$t" "$v"
        done
    } > "$rewritten"
    # Via a temp file, never straight into $EXPECTED: the redirection truncates on
    # open, so recorded_for would read back an empty baseline and drop every suite
    # this run did not measure.
    mv "$rewritten" "$EXPECTED"
    echo
    echo "wrote $EXPECTED"
fi

echo
echo "=== summary ==="
printf '%s\n' "${report[@]}" \
    | awk '{printf "  %-32s %-13s %9s %9s  %s\n", $1, $2, $3, $4, $5}'

if [[ "$failed" != 0 ]]; then
    echo
    echo "FAILED -- see DRIFT / PROOF-FAILED / UNRECORDED above." >&2
    exit 1
fi
