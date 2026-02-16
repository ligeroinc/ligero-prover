/*
 * Copyright (C) 2023-2026 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <runtime.hpp>
#include <opcode.hpp>

namespace ligero::vm {

void undefined(opcode code) {
    std::cout << "Undefined instruction: " << opcode::to_string(code.tag) << std::endl;
    throw wasm_trap("Undefined");
}

template <typename Context>
struct opcode_interpreter {
    using var = typename Context::witness_type;
    using opcode_func = exec_result (opcode_interpreter::*)(opcode);

    opcode_interpreter(Context& ctx)
        : ctx_(ctx),
          backend_(ctx.backend()),
          opcode_counter_{}
        { }

    void increase_opcode_count(opcode c) { ++opcode_counter_[c.tag]; }

    void display_opcode_count() const {
        std::vector<std::pair<opcode::kind, size_t>> compute_entries;
        std::vector<std::pair<opcode::kind, size_t>> control_entries;

        for (size_t i = 0; i < opcode::total_size; ++i) {
            if (opcode_counter_[i] > 0) {
                if (i < opcode::local_get) {
                    compute_entries.emplace_back(static_cast<opcode::kind>(i), opcode_counter_[i]);
                }
                else {
                    control_entries.emplace_back(static_cast<opcode::kind>(i), opcode_counter_[i]);
                }
            }
        }

        // Sort descending by count
        std::sort(compute_entries.begin(), compute_entries.end(),
                  [](auto a, auto b) { return a.second > b.second; });
        std::sort(control_entries.begin(), control_entries.end(),
                  [](auto a, auto b) { return a.second > b.second; });

        // Print table
        size_t subtotal = 0;

        std::cout << "Opcode usage summary (arithmetic):\n";
        std::cout << "--------------------------------" << std::endl;
        for (auto [op, count] : compute_entries) {
            subtotal += count;
            std::cout << std::setw(24) << std::left << opcode::to_string(op)
                      << ": " << count << "\n";
        }
        std::cout << std::setw(24) << std::left
                  << "Subtotal" << ": " << subtotal << std::endl << std::endl;

        subtotal = 0;

        std::cout << "Opcode usage summary (control):\n";
        std::cout << "--------------------------------" << std::endl;
        for (auto [op, count] : control_entries) {
            subtotal += count;
            std::cout << std::setw(24) << std::left << opcode::to_string(op)
                      << ": " << count << "\n";
        }
        std::cout << std::setw(24) << std::left
                  << "Subtotal" << ": " << subtotal << std::endl;

    }

    exec_result exec_unreachable(opcode ins) {
        std::cerr << "ERROR: Unreachable" << std::endl;
        throw wasm_trap("Unreachable");
    }

    exec_result exec_nop(opcode) {
        return exec_ok();
    }

    exec_result exec_drop(opcode ins) {
        ctx_.stack_pop();

        return exec_ok();
    }

    exec_result exec_select(opcode ins) {
        auto sc = ctx_.stack_pop();

        if (sc.is_val()) {
            if (sc.as_u32()) {
                ctx_.drop_n_below(1, 0);
            }
            else {
                ctx_.drop_n_below(1, 1);
            }
        }
        else {
            /** Compare the i32 condition with 0, then select! */
            auto c = ctx_.make_decomposed(std::move(sc), 32); // condition is always i32
            auto f = ctx_.make_witness(ctx_.stack_pop());
            auto t = ctx_.make_witness(ctx_.stack_pop());

            auto is_zero = backend_.bitwise_eqz(c);
            auto v = ctx_.backend().eval(is_zero * f + ~is_zero * t);

            ctx_.stack_push(std::move(v));
        }
        return exec_ok();
    }

    exec_result exec_inn_const(opcode i) {
        auto [type, k] = decode_constop(i);

        if (type == value_kind::i32) {
            u32 c = static_cast<u32>(k);
            ctx_.stack_push(c);
        }
        else {
            assert(type == value_kind::i64);
            ctx_.stack_push(k);
        }
        return exec_ok();
    }

    exec_result exec_inn_clz(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);

        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            if (type == value_kind::i32) {
                ctx_.stack_push(std::countl_zero(p->as_u32()));
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(std::countl_zero(p->as_u64()));
            }
            return {};
        }

        // ------------------------------------------------------------

        size_t num_bits = num_bits_of_kind(type);
        size_t msb      = num_bits - 1;

        auto bits       = ctx_.make_decomposed(std::move(sx), num_bits);
        var acc         = backend_.eval(~bits[msb]);
        var continue_   = backend_.duplicate(acc);

        for (int i = msb - 1; i >= 0; i--) {
            continue_ = backend_.eval(continue_ & ~bits[i]);
            acc  = backend_.eval(acc + continue_);
        }

        // assert(static_cast<u64>(acc.val()) == std::countl_zero(static_cast<u64>(x.val())));

        ctx_.stack_push(std::move(acc));
        return exec_ok();
    }

    exec_result exec_inn_ctz(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            if (type == value_kind::i32) {
                ctx_.stack_push(std::countr_zero(p->as_u32()));
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(std::countr_zero(p->as_u64()));
            }
            return {};
        }

        // ------------------------------------------------------------

        size_t num_bits = num_bits_of_kind(type);
        size_t msb = num_bits - 1;

        auto bits = ctx_.make_decomposed(std::move(sx), num_bits);
        var acc   = backend_.eval(~bits[0]);
        var cont  = backend_.duplicate(acc);
        for (int i = 1; i < num_bits; i++) {
            cont = backend_.eval(cont & ~bits[i]);
            acc  = backend_.eval(acc + cont);
        }

        // assert(static_cast<u64>(acc.val()) == std::countr_zero(static_cast<u64>(x.val())));

        ctx_.stack_push(std::move(acc));

        return exec_ok();
    }

    exec_result exec_inn_popcnt(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            if (type == value_kind::i32) {
                ctx_.stack_push(std::popcount(p->as_u32()));
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(std::popcount(p->as_u64()));
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        size_t msb = num_bits - 1;

        auto bits = ctx_.make_decomposed(std::move(sx), num_bits);

        auto acc  = backend_.eval(0u);
        for (int i = 0; i < num_bits; i++) {
            acc = backend_.eval(acc + bits[i]);
        }

        // assert(static_cast<u64>(acc.val()) == std::popcount(static_cast<u64>(x.val())));

        ctx_.stack_push(std::move(acc));
        return exec_ok();
    }

    exec_result exec_inn_add(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(px->as_u32() + py->as_u32());
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(px->as_u64() + py->as_u64());
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        const size_t num_overflowed_bits = num_bits + 1;

        auto x = ctx_.make_witness(std::move(sx));
        auto y = ctx_.make_witness(std::move(sy));

        auto overflowed = backend_.eval(x + y);
        auto bits = backend_.bit_decompose(overflowed, num_overflowed_bits);
        bits.drop_msb(1);

        ctx_.stack_push(std::move(bits));
        return exec_ok();
    }

    exec_result exec_inn_sub(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(px->as_u32() - py->as_u32());
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(px->as_u64() - py->as_u64());
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto x = ctx_.make_witness(std::move(sx));
        auto y = ctx_.make_witness(std::move(sy));

        if (type == value_kind::i32) {
            auto overflowed = backend_.eval((1ULL << 32) - y + x);

            auto bits = backend_.bit_decompose(overflowed, 33);
            bits.drop_msb(1);

            ctx_.stack_push(std::move(bits));
        }
        else {
            assert(type == value_kind::i64);

            // x - y mod 2^64 := 2^64 - y + x
            mpz_class *pow = backend_.manager().acquire_mpz();
            *pow = 1;
            *pow <<= 64;

            auto overflowed = backend_.eval(*pow - y + x);

            auto bits = backend_.bit_decompose(overflowed, 65);
            bits.drop_msb(1);
            backend_.manager().recycle_mpz(pow);

            ctx_.stack_push(std::move(bits));
        }

        return exec_ok();
    }

    exec_result exec_inn_mul(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(px->as_u32() * py->as_u32());
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(px->as_u64() * py->as_u64());
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto x = ctx_.make_witness(std::move(sx));
        auto y = ctx_.make_witness(std::move(sy));

        if (type == value_kind::i32) {
            auto overflow = backend_.eval(x * y);

            auto bits = backend_.bit_decompose(overflow, 64);
            bits.drop_msb(32);

            ctx_.stack_push(std::move(bits));
        }
        else {
            assert(type == value_kind::i64);

            auto big_result = backend_.eval(x * y);

            auto bits = backend_.bit_decompose(big_result, 128);
            bits.drop_msb(64);

            ctx_.stack_push(std::move(bits));
        }
        return exec_ok();
    }

    exec_result exec_inn_div_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u32>(static_cast<s32>(px->as_u32()) /
                                                     static_cast<s32>(py->as_u32())));
                }
                else {
                    assert(sign == sign_kind::unsign);
                    ctx_.stack_push(px->as_u32() / py->as_u32());
                }
            }
            else {
                assert(type == value_kind::i64);
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u64>(static_cast<s64>(px->as_u64()) /
                                                     static_cast<s64>(py->as_u64())));
                }
                else {
                    assert(sign == sign_kind::unsign);
                    ctx_.stack_push(px->as_u64() / py->as_u64());
                }
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        const size_t msb = num_bits - 1;
        const size_t num_overflowed_bits = num_bits + 1;

        auto x = ctx_.make_witness(std::move(sx));
        auto y = ctx_.make_witness(std::move(sy));

        if (sign == sign_kind::sign) {
            auto bx = backend_.bit_decompose(x, num_bits);
            auto by = backend_.bit_decompose(y, num_bits);

            mpz_class *pow = backend_.manager().acquire_mpz();
            *pow = 1;
            *pow <<= num_bits;
            auto abs_x = backend_.eval(bx[msb] * (*pow - x) + ~bx[msb] * x);
            auto abs_y = backend_.eval(by[msb] * (*pow - y) + ~by[msb] * y);

            auto [q, r] = backend_.idivide_qr(abs_x, abs_y);

            auto abs_y_bit = backend_.bit_decompose(abs_y, num_bits);
            auto br        = backend_.bit_decompose(r, num_bits);
            auto [gt, eq] = backend_.bitwise_gt(abs_y_bit, br, sign);

            backend_.assert_const(gt, 1);
            backend_.assert_const(eq, 0);

            auto neg   = backend_.bitwise_xor(bx[msb], by[msb]);
            auto ovf_q = backend_.eval(*pow - q);

            auto bneg_q = backend_.bit_decompose(ovf_q, num_overflowed_bits);
            bneg_q.drop_msb(1);
            auto neg_q = backend_.bit_compose(bneg_q);
            auto res_q = backend_.eval(neg * neg_q + ~neg * q);

            backend_.manager().recycle_mpz(pow);

            ctx_.stack_push(std::move(res_q));
        }
        else {
            assert(sign == sign_kind::unsign);
            auto [q, r] = backend_.idivide_qr(x, y);

            auto by = backend_.bit_decompose(y, num_bits);
            auto br = backend_.bit_decompose(r, num_bits);
            auto [gt, eq] = backend_.bitwise_gt(by, br, sign);

            backend_.assert_const(gt, 1);
            backend_.assert_const(eq, 0);

            ctx_.stack_push(std::move(q));
            // assert(static_cast<u32>(x.val()) /
            //        static_cast<u32>(y.val()) == static_cast<u32>(q.val()));
        }
        return exec_ok();
    }

    exec_result exec_inn_rem_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u32>(static_cast<s32>(px->as_u32()) %
                                                     static_cast<s32>(py->as_u32())));
                }
                else {
                    ctx_.stack_push(px->as_u32() % py->as_u32());
                }
            }
            else {
                assert(type == value_kind::i64);
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u64>(static_cast<s64>(px->as_u64()) %
                                                     static_cast<s64>(py->as_u64())));
                }
                else {
                    ctx_.stack_push(px->as_u64() % py->as_u64());
                }
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        const size_t msb = num_bits - 1;
        const size_t num_overflowed_bits = num_bits + 1;

        auto x = ctx_.make_witness(std::move(sx));
        auto y = ctx_.make_witness(std::move(sy));

        if (sign == sign_kind::sign) {
            auto bx = backend_.bit_decompose(x, num_bits);
            auto by = backend_.bit_decompose(y, num_bits);

            mpz_class *pow = backend_.manager().acquire_mpz();
            *pow = 1;
            *pow <<= num_bits;
            auto abs_x = backend_.eval(bx[msb] * (*pow - x) + ~bx[msb] * x);
            auto abs_y = backend_.eval(by[msb] * (*pow - y) + ~by[msb] * y);

            auto [q, r] = backend_.idivide_qr(abs_x, abs_y);

            auto abs_y_bit = backend_.bit_decompose(abs_y, num_bits);
            auto br        = backend_.bit_decompose(r, num_bits);
            auto [gt, eq] = backend_.bitwise_gt(abs_y_bit, br, sign);

            backend_.assert_const(gt, 1);
            backend_.assert_const(eq, 0);

            auto ovf_r = backend_.eval(*pow - r);
            auto bneg_r = backend_.bit_decompose(ovf_r, num_overflowed_bits);
            bneg_r.drop_msb(1);
            auto neg_r = backend_.bit_compose(bneg_r);
            auto res_r = backend_.eval(bx[msb] * neg_r + ~bx[msb] * r);

            backend_.manager().recycle_mpz(pow);

            ctx_.stack_push(std::move(res_r));
        }
        else {
            auto [q, r] = backend_.idivide_qr(x, y);

            auto by = backend_.bit_decompose(y, num_bits);
            auto br = backend_.bit_decompose(r, num_bits);
            auto [gt, eq] = backend_.bitwise_gt(by, br, sign);

            backend_.assert_const(gt, 1);
            backend_.assert_const(eq, 0);

            ctx_.stack_push(std::move(r));
        }

        return exec_ok();
    }

    exec_result exec_inn_and(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(px->as_u32() & py->as_u32());
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(px->as_u64() & py->as_u64());
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        size_t num_bits = num_bits_of_kind(type);

        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        zkp::decomposed_bits out;
        for (size_t i = 0; i < num_bits; i++) {
            out.push_back(backend_.eval(x[i] & y[i]));
        }

        ctx_.stack_push(std::move(out));
        return exec_ok();
    }

    exec_result exec_inn_or(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(px->as_u32() | py->as_u32());
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(px->as_u64() | py->as_u64());
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);

        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        zkp::decomposed_bits out;
        for (size_t i = 0; i < num_bits; i++) {
            out.push_back(backend_.eval(x[i] + y[i] - (x[i] & y[i])));
        }
        ctx_.stack_push(std::move(out));

        // std::cout << "or ";
        // std::cout << " " << x.val() << " " << y.val() << " " << acc.val() << std::endl;
        // ctx_.show_stack();
        return exec_ok();
    }

    exec_result exec_inn_xor(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(px->as_u32() ^ py->as_u32());
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(px->as_u64() ^ py->as_u64());
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);

        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        zkp::decomposed_bits out;
        for (size_t i = 0; i < num_bits; i++) {
            auto b = backend_.bitwise_xor(x[i], y[i]);
            out.push_back(std::move(b));
        }

        ctx_.stack_push(std::move(out));
        return exec_ok();
    }

    exec_result exec_inn_shl(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto shift = ctx_.stack_pop();
        auto sx    = ctx_.stack_pop();

        // ------------------------------------------------------------

        size_t num_bits = num_bits_of_kind(type);
        u32 n = ctx_.make_numeric(std::move(shift)).as_u32();
        n = n % num_bits;

        // ------------------------------------------------------------

        auto *px = sx.get_if_numeric();

        if (px) {
            if (type == value_kind::i32) {
                ctx_.stack_push(px->as_u32() << n);
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(px->as_u64() << n);
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto x = ctx_.make_decomposed(std::move(sx), num_bits);

        auto zero = backend_.eval(0u);
        x.push_lsb(zero, n);
        x.drop_msb(n);

        ctx_.stack_push(std::move(x));

        // std::cout << "shiftl ";
        // std::cout << " " << x.val() << " " << shift.val();
        // ctx_.show_stack();

        return exec_ok();
    }

    exec_result exec_inn_shr_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto shift = ctx_.stack_pop();
        auto sx    = ctx_.stack_pop();

        // ------------------------------------------------------------

        size_t num_bits = num_bits_of_kind(type);
        size_t msb      = num_bits - 1;
        u32    n        = ctx_.make_numeric(std::move(shift)).as_u32();

        n = n % num_bits;

        // ------------------------------------------------------------

        auto *px = sx.get_if_numeric();

        if (px) {
            if (type == value_kind::i32) {
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(
                        static_cast<u32>(static_cast<s32>(px->as_u32()) >> n));
                }
                else {
                    ctx_.stack_push(px->as_u32() >> n);
                }
            }
            else {
                assert(type == value_kind::i64);
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(
                        static_cast<u64>(static_cast<s64>(px->as_u64()) >> n));
                }
                else {
                    ctx_.stack_push(px->as_u64() >> n);
                }
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto x = ctx_.make_decomposed(std::move(sx), num_bits);

        zkp::decomposed_bits shifted_bits;
        if (sign == sign_kind::sign) {
            auto pad = backend_.duplicate(x[msb]);
            x.drop_lsb(n);
            x.push_msb(pad, n);
        }
        else {
            auto zero = backend_.eval(0u);
            x.drop_lsb(n);
            x.push_msb(zero, n);
        }

        ctx_.stack_push(std::move(x));
        return exec_ok();
    }

    exec_result exec_inn_rotl(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto shift = ctx_.stack_pop();
        auto sx    = ctx_.stack_pop();

        // ------------------------------------------------------------

        size_t num_bits = num_bits_of_kind(type);
        u32 n = ctx_.make_numeric(std::move(shift)).as_u32();
        n = n % num_bits;

        // ------------------------------------------------------------

        auto *px = sx.get_if_numeric();

        if (px) {
            if (type == value_kind::i32) {
                ctx_.stack_push(std::rotl(px->as_u32(), n));
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(std::rotl(px->as_u64(), n));
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto x = ctx_.make_decomposed(std::move(sx), num_bits);

        zkp::decomposed_bits shifted_bits;
        for (size_t i = 0; i < n; i++) {
            shifted_bits.push_back(std::move(x[num_bits - n + i]));
        }

        for (size_t i = n; i < num_bits; i++) {
            shifted_bits.push_back(std::move(x[i - n]));
        }

        ctx_.stack_push(std::move(shifted_bits));
        return exec_ok();
    }

    exec_result exec_inn_rotr(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto shift = ctx_.stack_pop();
        auto sx    = ctx_.stack_pop();

        // ------------------------------------------------------------

        size_t num_bits = num_bits_of_kind(type);
        size_t msb      = num_bits - 1;
        u32    n        = ctx_.make_numeric(std::move(shift)).as_u32();

        n = n % num_bits;

        // ------------------------------------------------------------

        auto *px = sx.get_if_numeric();

        if (px) {
            if (type == value_kind::i32) {
                ctx_.stack_push(std::rotr(px->as_u32(), n));
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(std::rotr(px->as_u64(), n));
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto x = ctx_.make_decomposed(std::move(sx), num_bits);

        zkp::decomposed_bits shifted_bits;
        for (u32 i = n; i < num_bits; i++) {
            shifted_bits.push_back(std::move(x[i]));
        }
        for (u32 i = 0; i < n; i++) {
            shifted_bits.push_back(std::move(x[i]));
        }

        ctx_.stack_push(std::move(shifted_bits));
        return exec_ok();
    }

    exec_result exec_inn_eqz(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            if (type == value_kind::i32) {
                ctx_.stack_push(u32{ p->as_u32() == 0U });
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(u64{ p->as_u64() == 0ULL });
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto x = ctx_.make_decomposed(std::move(sx), num_bits);

        auto acc = backend_.eval(~x[0]);
        for (size_t i = 1; i < num_bits; i++) {
            acc = backend_.eval(acc & ~x[i]);
        }

        ctx_.stack_push(std::move(acc));
        return exec_ok();
    }

    exec_result exec_inn_eq(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

            // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(u32{ px->as_u32() == py->as_u32() });
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(u32{ px->as_u64() == py->as_u64() });
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        auto eq = backend_.bitwise_eq(x, y);

        ctx_.stack_push(std::move(eq));
        return exec_ok();
    }

    exec_result exec_inn_ne(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                ctx_.stack_push(u32{ px->as_u32() != py->as_u32() });
            }
            else {
                assert(type == value_kind::i64);
                ctx_.stack_push(u32{ px->as_u64() != py->as_u64() });
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        auto neq = backend_.eval(~backend_.bitwise_eq(x, y));

        ctx_.stack_push(std::move(neq));
        return exec_ok();
    }

    exec_result exec_inn_lt_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u32>(static_cast<s32>(px->as_u32()) < static_cast<s32>(py->as_u32())));
                }
                else {
                    ctx_.stack_push(static_cast<u32>(px->as_u32() < py->as_u32()));
                }
            }
            else {
                assert(type == value_kind::i64);
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u64>(static_cast<s64>(px->as_u64()) < static_cast<s64>(py->as_u64())));
                }
                else {
                    ctx_.stack_push(static_cast<u64>(px->as_u64() < py->as_u64()));
                }
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        auto [gt, eq] = backend_.bitwise_gt(x, y, sign);
        auto lt = backend_.eval(~(gt + eq));

        ctx_.stack_push(std::move(lt));
        return exec_ok();
    }

    exec_result exec_inn_gt_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u32>(static_cast<s32>(px->as_u32()) > static_cast<s32>(py->as_u32())));
                }
                else {
                    ctx_.stack_push(static_cast<u32>(px->as_u32() > py->as_u32()));
                }
            }
            else {
                assert(type == value_kind::i64);
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u64>(static_cast<s64>(px->as_u64()) > static_cast<s64>(py->as_u64())));
                }
                else {
                    ctx_.stack_push(static_cast<u64>(px->as_u64() > py->as_u64()));
                }
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        auto [gt, _] = backend_.bitwise_gt(x, y, sign);

        ctx_.stack_push(std::move(gt));
        return exec_ok();
    }

    exec_result exec_inn_le_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u32>(static_cast<s32>(px->as_u32()) <= static_cast<s32>(py->as_u32())));
                }
                else {
                    ctx_.stack_push(static_cast<u32>(px->as_u32() <= py->as_u32()));
                }
            }
            else {
                assert(type == value_kind::i64);
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u64>(static_cast<s64>(px->as_u64()) <= static_cast<s64>(py->as_u64())));
                }
                else {
                    ctx_.stack_push(static_cast<u64>(px->as_u64() <= py->as_u64()));
                }
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        auto [gt, _] = backend_.bitwise_gt(x, y, sign);
        auto le = backend_.eval(~gt);

        ctx_.stack_push(std::move(le));
        return exec_ok();
    }

    exec_result exec_inn_ge_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sy = ctx_.stack_pop();
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------
        auto *px = sx.get_if_numeric();
        auto *py = sy.get_if_numeric();

        if (px && py) {
            if (type == value_kind::i32) {
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u32>(static_cast<s32>(px->as_u32()) >= static_cast<s32>(py->as_u32())));
                }
                else {
                    ctx_.stack_push(static_cast<u32>(px->as_u32() >= py->as_u32()));
                }
            }
            else {
                assert(type == value_kind::i64);
                if (sign == sign_kind::sign) {
                    ctx_.stack_push(static_cast<u64>(static_cast<s64>(px->as_u64()) >= static_cast<s64>(py->as_u64())));
                }
                else {
                    ctx_.stack_push(static_cast<u64>(px->as_u64() >= py->as_u64()));
                }
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto x = ctx_.make_decomposed(std::move(sx), num_bits);
        auto y = ctx_.make_decomposed(std::move(sy), num_bits);

        auto [gt, eq] = backend_.bitwise_gt(x, y, sign);
        auto ge = backend_.eval(gt + eq);

        ctx_.stack_push(std::move(ge));
        return exec_ok();
    }

    exec_result exec_inn_extend8_s(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            if (type == value_kind::i32) {
                u32 result = static_cast<s32>(static_cast<signed char>(p->as_u32()));
                ctx_.stack_push(result);
            }
            else {
                assert(type == value_kind::i64);
                u64 result = static_cast<s64>(static_cast<signed char>(p->as_u64()));
                ctx_.stack_push(result);
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto bits = ctx_.make_decomposed(std::move(sx), num_bits);
        bits.drop_msb(num_bits - 8);

        for (size_t i = 8; i < num_bits; i++) {
            bits.push_back(backend_.duplicate(bits[7]));
        }

        ctx_.stack_push(std::move(bits));
        return exec_ok();
    }

    exec_result exec_inn_extend16_s(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            if (type == value_kind::i32) {
                u32 result = static_cast<s32>(static_cast<int16_t>(p->as_u32()));
                ctx_.stack_push(result);
            }
            else {
                assert(type == value_kind::i64);
                u64 result = static_cast<s64>(static_cast<uint16_t>(p->as_u64()));
                ctx_.stack_push(result);
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        const size_t num_bits = num_bits_of_kind(type);
        auto bits = ctx_.make_decomposed(std::move(sx), num_bits);
        bits.drop_msb(num_bits - 16);

        for (size_t i = 16; i < num_bits; i++) {
            bits.push_back(backend_.duplicate(bits[15]));
        }

        ctx_.stack_push(std::move(bits));
        return exec_ok();
    }

    // Sign extending an 64bit integer to 64bit
    exec_result exec_i64_extend32_s(opcode ins) {
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            u32 mask = p->as_u64() & 0xFFFFFFFFu;
            u64 result = static_cast<s32>(mask);
            ctx_.stack_push(result);
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto bits = ctx_.make_decomposed(std::move(sx), 64);
        bits.drop_msb(32);

        for (u32 i = 32; i < 64; i++) {
            bits.push_back(backend_.duplicate(bits[31]));
        }

        ctx_.stack_push(std::move(bits));
        return exec_ok();
    }

    exec_result exec_i64_extend_i32_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            if (sign == sign_kind::sign) {
                u64 result = static_cast<s64>(static_cast<s32>(p->as_u32()));
                ctx_.stack_push(result);
            }
            else {
                u64 result = p->as_u32();
                ctx_.stack_push(result);
            }
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto bits = ctx_.make_decomposed(std::move(sx), 32);

        if (sign == sign_kind::sign) {
            for (u32 i = 32; i < 64; i++) {
                bits.push_back(backend_.duplicate(bits[31]));
            }
        }
        else {
            auto zero = backend_.eval(0u);
            bits.push_msb(zero, 32);
        }

        ctx_.stack_push(std::move(bits));
        return exec_ok();
    }

    exec_result exec_i32_wrap_i64(opcode ins) {
        auto sx = ctx_.stack_pop();

        // ------------------------------------------------------------

        if (auto *p = sx.get_if_numeric()) {
            u32 result = static_cast<u32>(p->as_u64());
            ctx_.stack_push(result);
            return exec_ok();
        }

        // ------------------------------------------------------------

        auto bits = ctx_.make_decomposed(std::move(sx), 64);
        bits.drop_msb(32);

        ctx_.stack_push(std::move(bits));
        return exec_ok();
    }


    // ------------------------------------------------------------

    exec_result exec_fnn_const(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_eq(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_ne(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_lt(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_gt(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_le(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_ge(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_abs(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_neg(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_ceil(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_floor(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_trunc(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_nearest(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_sqrt(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_add(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_sub(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_mul(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_div(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_min(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_max(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_fnn_copysign(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f32_convert_i32_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f32_convert_i32_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f32_convert_i64_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f32_convert_i64_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f32_demote_f64(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f64_convert_i32_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f64_convert_i32_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f64_convert_i64_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f64_convert_i64_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f64_promote_f32(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i32_reinterpret_f32(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_reinterpret_f64(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f32_reinterpret_i32(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_f64_reinterpret_i64(opcode ins) {
        undefined(ins);
        return exec_ok();
    }


    exec_result exec_i32_trunc_f32_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i32_trunc_f32_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i32_trunc_f64_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i32_trunc_f64_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_f32_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_f32_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_f64_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_f64_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }


    exec_result exec_i32_trunc_sat_f32_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i32_trunc_sat_f32_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i32_trunc_sat_f64_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i32_trunc_sat_f64_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_sat_f32_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_sat_f32_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_sat_f64_s(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_i64_trunc_sat_f64_u(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    // ------------------------------------------------------------

    exec_result exec_local_get(opcode ins) {
        auto [x] = decode_index(ins);
        auto *cf = ctx_.current_frame();

        auto& local = cf->locals[x];

        ctx_.stack_push(std::visit(prelude::overloaded {
                [](std::unique_ptr<wasm_frame>& v) -> stack_value {
                    throw wasm_trap("local_get: Unexpected frame pointer");
                },
                [](auto& x) { return stack_value{ x }; }
            }, local.data()));

        // ctx_.show_stack();
        return exec_ok();
    }

    exec_result exec_local_set(opcode ins) {
        auto [x] = decode_index(ins);
        auto *cf = ctx_.current_frame();

        cf->locals[x] = ctx_.stack_pop();

        // std::cout << "local.set[" << x << "]" << std::endl;
        // ctx_.show_stack();
        return exec_ok();
    }

    exec_result exec_local_tee(opcode ins) {
        auto [x] = decode_index(ins);
        auto *cf = ctx_.current_frame();

        auto& v = ctx_.stack_peek();
        cf->locals[x] = std::visit(prelude::overloaded {
                    [](std::unique_ptr<wasm_frame>& v) -> stack_value {
                        throw wasm_trap("local_tee: Unexpected frame pointer");
                    },
                    [](auto& x) { return stack_value{ x }; }
                }, v.data());

        // std::cout << "local.tee[" << x << "]" << std::endl;
        // ctx_.show_stack();
        return exec_ok();
    }

    exec_result exec_global_get(opcode ins) {
        auto [x] = decode_index(ins);
        auto *cf = ctx_.current_frame();
        address_t a = cf->module->globaladdrs[x];
        const global_instance& glob = ctx_.store()->globals[a];

        ctx_.stack_push(glob.val);

        // ctx_.show_stack();
        return exec_ok();
    }

    exec_result exec_global_set(opcode ins) {
        auto [x] = decode_index(ins);
        address_t a = ctx_.current_frame()->module->globaladdrs[x];
        global_instance& glob = ctx_.store()->globals[a];
        auto val = ctx_.stack_pop().as_numeric();

        glob.val = val;

        return exec_ok();
    }


    // ------------------------------------------------------------


    exec_result exec_ref_null(opcode) {
        ctx_.stack_push(reference_t{});
        return exec_ok();
    }

    exec_result exec_ref_is_null(opcode) {
        reference_t val = ctx_.stack_pop().as_ref();
        u32 is_null = !val;
        ctx_.stack_push(is_null);
        return exec_ok();
    }

    exec_result exec_ref_func(opcode ins) {
        auto [i] = decode_index(ins);
        auto f = ctx_.current_frame();
        address_t a = f->module->funcaddrs[i];
        ctx_.stack_push(reference_t{ a });
        return exec_ok();
    }


    // ------------------------------------------------------------


    exec_result exec_table_get(opcode ins) {
        auto [x] = decode_index(ins);

        auto f = ctx_.current_frame();
        address_t addr = f->module->tableaddrs[x];
        table_instance& tab = ctx_.store()->tables[addr];

        u32 i = ctx_.stack_pop().as_u32();

        if (i >= tab.elem.size()) {
            throw wasm_trap("table_get: index out of range");
        }

        reference_t ref = tab.elem[i];
        ctx_.stack_push(ref);
        return exec_ok();
    }

    exec_result exec_table_set(opcode ins) {
        auto [x] = decode_index(ins);

        auto f = ctx_.current_frame();
        address_t addr = f->module->tableaddrs[x];
        table_instance& tab = ctx_.store()->tables[addr];

        reference_t val = ctx_.stack_pop().as_ref();
        u32 i = ctx_.stack_pop().as_u32();

        if (i >= tab.elem.size()) {
            throw wasm_trap("table_get: index out of range");
        }

        tab.elem[i] = val;
        return exec_ok();
    }

    exec_result exec_table_size(opcode ins) {
        auto [x] = decode_index(ins);

        auto f = ctx_.current_frame();
        address_t addr = f->module->tableaddrs[x];
        table_instance& tab = ctx_.store()->tables[addr];

        u32 sz = tab.elem.size();
        ctx_.stack_push(sz);
        return exec_ok();
    }

    exec_result exec_table_grow(opcode ins) {
        auto [x] = decode_index(ins);

        auto f = ctx_.current_frame();
        address_t addr = f->module->tableaddrs[x];
        table_instance& tab = ctx_.store()->tables[addr];

        u32 sz = tab.elem.size();
        u32 n = ctx_.stack_pop().as_u32();
        reference_t val = ctx_.stack_pop().as_ref();

        try {
            // TODO: check max table size in limit
            for (u32 i = 0; i < n; i++) {
                tab.elem.push_back(val);
            }
            ctx_.stack_push(sz);
        }
        catch (...) {
            ctx_.stack_push(static_cast<u32>(-1));
        }

        return exec_ok();
    }

    exec_result exec_table_fill(opcode ins) {
        auto [x] = decode_index(ins);

        auto f = ctx_.current_frame();
        address_t ta = f->module->tableaddrs[x];
        table_instance& tab = ctx_.store()->tables[ta];

        u32 n = ctx_.stack_pop().as_u32();
        reference_t val = ctx_.stack_pop().as_ref();
        u32 i = ctx_.stack_pop().as_u32();

        if (i + n > tab.elem.size()) {
            throw wasm_trap("table_fill: index out of bound");
        }

        for (u32 j = 0; j < n; j++, i++) {
            tab.elem[i] = val;
        }

        return exec_ok();
    }

    exec_result exec_table_copy(opcode ins) {
        auto [dst, src] = decode_index2(ins);

        auto f = ctx_.current_frame();
        address_t ta = f->module->tableaddrs[dst];
        address_t tb = f->module->tableaddrs[src];
        table_instance& tab_x = ctx_.store()->tables[ta];
        table_instance& tab_y = ctx_.store()->tables[tb];

        u32 n = ctx_.stack_pop().as_u32();
        u32 s = ctx_.stack_pop().as_u32();
        u32 d = ctx_.stack_pop().as_u32();

        if (s + n > tab_y.elem.size() or d + n > tab_x.elem.size()) {
            throw wasm_trap("table_copy: index out of bound");
        }

        if (d <= s) {
            for (u32 j = 0; j < n; j++) {
                tab_x.elem[d++] = tab_y.elem[s++];
            }
        }
        else {
            for (; n > 0; n--) {
                tab_x.elem[d + n - 1] = tab_y.elem[s + n - 1];
            }
        }
        return exec_ok();
    }

    exec_result exec_table_init(opcode ins) {
        auto [seg_idx, tab_idx] = decode_index2(ins);

        auto f = ctx_.current_frame();
        address_t ta = f->module->tableaddrs[tab_idx];
        address_t ea = f->module->elemaddrs[seg_idx];
        table_instance& tab = ctx_.store()->tables[ta];
        element_instance& elem = ctx_.store()->elements[ea];

        u32 n = ctx_.stack_pop().as_u32();
        u32 s = ctx_.stack_pop().as_u32();
        u32 d = ctx_.stack_pop().as_u32();

        if (s + n > elem.elem.size() or d + n > tab.elem.size()) {
            throw wasm_trap("table_init: index out of bound");
        }

        for (; n > 0; n--) {
            tab.elem[d++] = elem.elem[s++];
        }
        return exec_ok();
    }

    exec_result exec_elem_drop(opcode ins) {
        auto [x] = decode_index(ins);

        auto f = ctx_.current_frame();
        address_t a = f->module->tableaddrs[x];
        element_instance& elem = ctx_.store()->elements[a];
        elem.elem.clear();

        return exec_ok();
    }


    // ------------------------------------------------------------


    exec_result exec_memory_size(opcode ins) {
        auto [idx] = decode_index(ins);
        auto *f = ctx_.current_frame();
        address_t a = f->module->memaddrs[idx];
        const auto& mem = ctx_.store()->memorys[a];
        u32 sz = mem.data.size() / memory_instance::page_size;
        ctx_.stack_push(u32{sz});
        return exec_ok();
    }

    exec_result exec_memory_grow(opcode ins) {
        auto [idx] = decode_index(ins);
        auto *f = ctx_.current_frame();
        address_t a = f->module->memaddrs[idx];
        auto& mem = ctx_.store()->memorys[a];

        u32 sz = mem.data.size() / memory_instance::page_size;
        u32 n = ctx_.stack_pop().as_u32();

        u32 len = sz + n;
        assert(len >= sz);

        if (len > 65536 || (mem.kind.limit.max && len > mem.kind.limit.max)) {
            ctx_.stack_push(std::numeric_limits<u32>::max());
        }
        else {
            mem.data.resize(len * memory_instance::page_size);
            ctx_.stack_push(sz);
        }

        return exec_ok();
    }

    exec_result exec_memory_fill(opcode ins) {
        auto [idx] = decode_index(ins);
        auto *f = ctx_.current_frame();
        address_t a = f->module->memaddrs[idx];
        auto& mem = ctx_.store()->memorys[a];

        u32 n   = ctx_.stack_pop().as_u32();
        u32 val = ctx_.stack_pop().as_u32();
        u32 d   = ctx_.stack_pop().as_u32();

        if (d + n > mem.data.size()) {
            throw wasm_trap("memory_fill: Invalid address");
        }
        std::fill_n(mem.data.begin() + d, n, val);
        return exec_ok();
    }

    exec_result exec_memory_copy(opcode ins) {
        auto [dst_index, src_index] = decode_index2(ins);

        // Current WASM spec only support one linear memory, so it must be 0
        assert(src_index == 0);
        assert(dst_index == 0);

        auto& mem = ctx_.store()->memorys[0];
        u32 count = ctx_.stack_pop().as_u32();
        u32 src   = ctx_.stack_pop().as_u32();
        u32 dst   = ctx_.stack_pop().as_u32();

        mem.memcpy_secrets(dst, src, count);
        return exec_ok();
    }

    exec_result exec_memory_init(opcode ins) {
        auto [idx] = decode_index(ins);
        auto *f = ctx_.current_frame();
        address_t ma = f->module->memaddrs[0];
        auto& mem = ctx_.store()->memorys[ma];

        address_t da = f->module->dataaddrs[idx];
        auto& data = ctx_.store()->datas[da];

        u32 n = ctx_.stack_pop().as_u32();
        u32 s = ctx_.stack_pop().as_u32();
        u32 d = ctx_.stack_pop().as_u32();

        if (s + n > data.data.size() or d + n > mem.data.size()) {
            throw wasm_trap("memory_init: Invalid address");
        }
        std::copy(data.data.begin() + s, data.data.begin() + s + n, mem.data.begin() + d);
        return exec_ok();
    }

    exec_result exec_data_drop(opcode ins) {
        auto [idx] = decode_index(ins);
        auto *f = ctx_.current_frame();
        address_t da = f->module->dataaddrs[idx];
        auto& data = ctx_.store()->datas[da];
        data.data.clear();
        return exec_ok();
    }

    template <typename From, typename To>
    void do_load(u32 offset) {
        auto *f = ctx_.current_frame();
        address_t a = f->module->memaddrs[0];
        memory_instance& mem = ctx_.store()->memorys[a];

        auto tmp = ctx_.stack_pop();

        u64 i  = ctx_.make_numeric(std::move(tmp)).as_u32();
        u64 ea = i + offset;
        u64 n  = sizeof(From);
        if (ea + n > mem.data.size()) {
            throw wasm_trap("Invalid memory address");
        }

        To c = ctx_.template memory_load<From>(ea);

        if (mem.contains_secret(ea, ea + n)) {
            // std::cout << "Loading secret from mem[" << ea << "]" << std::endl;
            ctx_.stack_push(ctx_.make_witness(c));
        }
        else {
            ctx_.stack_push(c);
        }
    }

    exec_result exec_inn_load(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        if (type == value_kind::i32) {
            do_load<u32, u32>(offset);
        }
        else {
            assert(type == value_kind::i64);
            do_load<u64, u64>(offset);
        }
        return exec_ok();
    }

    exec_result exec_fnn_load(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_inn_load8_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        if (type == value_kind::i32) {
            if (sign == sign_kind::sign) {
                do_load<s8, u32>(offset);
            }
            else {
                do_load<u8, u32>(offset);
            }
        }
        else {
            assert(type == value_kind::i64);
            if (sign == sign_kind::sign) {
                do_load<s8, u64>(offset);
            }
            else {
                do_load<u8, u64>(offset);
            }
        }
        return exec_ok();
    }

    exec_result exec_inn_load16_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        if (type == value_kind::i32) {
            if (sign == sign_kind::sign) {
                do_load<s16, u32>(offset);
            }
            else {
                do_load<u16, u32>(offset);
            }
        }
        else {
            assert(type == value_kind::i64);
            if (sign == sign_kind::sign) {
                do_load<s16, u64>(offset);
            }
            else {
                do_load<u16, u64>(offset);
            }
        }
        return exec_ok();
    }

    exec_result exec_i64_load32_sx(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        if (sign == sign_kind::sign) {
            do_load<s32, u64>(offset);
        }
        else {
            do_load<u32, u64>(offset);
        }
        return exec_ok();
    }

    template <typename From, typename To>
    exec_result do_store(u32 offset) {
        auto *f = ctx_.current_frame();
        address_t a = f->module->memaddrs[0];
        memory_instance& mem = ctx_.store()->memorys[a];

        auto tmp  = ctx_.stack_pop();
        auto addr = ctx_.stack_pop();

        u64 i  = ctx_.make_numeric(std::move(addr)).as_u32();
        u64 ea = i + offset;
        u64 n  = sizeof(To);

        if (ea + n > mem.data.size()) {
            throw wasm_trap("Invalid memory address");
        }

        if (tmp.is_val()) {
            mem.unmark_closed(ea, ea + n);
        }
        else {
            mem.mark_secret_closed(ea, ea + n);
        }

        To c;
        if constexpr (std::is_same_v<From, u32>) {
            u32 num = ctx_.make_numeric(std::move(tmp)).as_u32();
            c = static_cast<To>(num);
        }
        else if constexpr (std::is_same_v<From, u64>) {
            u64 num = ctx_.make_numeric(std::move(tmp)).as_u64();
            c = static_cast<To>(num);
        }
        else {
            static_assert(false, "Unexpected conversion type");
        }

        ctx_.template memory_store<To>(ea, c);

        // std::cout << "Store Mem[" << ea << "] = " << c << std::endl;
        return exec_ok();
    }

    exec_result exec_inn_store(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        if (type == value_kind::i32) {
            return do_store<u32, u32>(offset);
        }
        else {
            assert(type == value_kind::i64);
            return do_store<u64, u64>(offset);
        }
    }

    exec_result exec_fnn_store(opcode ins) {
        undefined(ins);
        return exec_ok();
    }

    exec_result exec_inn_store8(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        if (type == value_kind::i32) {
            return do_store<u32, u8>(offset);
        }
        else {
            assert(type == value_kind::i64);
            return do_store<u64, u8>(offset);
        }
    }

    exec_result exec_inn_store16(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        if (type == value_kind::i32) {
            return do_store<u32, u16>(offset);
        }
        else {
            assert(type == value_kind::i64);
            return do_store<u64, u16>(offset);
        }
    }

    exec_result exec_i64_store32(opcode ins) {
        auto [type, sign, align, offset] = decode_opcode(ins);
        return do_store<u64, u32>(offset);
    }


    static constexpr std::array<opcode_func, opcode::total_size> opcode_dispatch_table = {
        &opcode_interpreter::exec_nop,

        // Constants
        &opcode_interpreter::exec_inn_const,

        // Integer Unary
        &opcode_interpreter::exec_inn_clz,
        &opcode_interpreter::exec_inn_ctz,
        &opcode_interpreter::exec_inn_popcnt,
        &opcode_interpreter::exec_inn_eqz,

        // Integer Binary
        &opcode_interpreter::exec_inn_add,
        &opcode_interpreter::exec_inn_sub,
        &opcode_interpreter::exec_inn_mul,
        &opcode_interpreter::exec_inn_div_sx,
        &opcode_interpreter::exec_inn_rem_sx,
        &opcode_interpreter::exec_inn_and,
        &opcode_interpreter::exec_inn_or,
        &opcode_interpreter::exec_inn_xor,
        &opcode_interpreter::exec_inn_shl,
        &opcode_interpreter::exec_inn_shr_sx,
        &opcode_interpreter::exec_inn_rotl,
        &opcode_interpreter::exec_inn_rotr,
        &opcode_interpreter::exec_inn_eq,
        &opcode_interpreter::exec_inn_ne,
        &opcode_interpreter::exec_inn_lt_sx,
        &opcode_interpreter::exec_inn_gt_sx,
        &opcode_interpreter::exec_inn_le_sx,
        &opcode_interpreter::exec_inn_ge_sx,

        // Extensions
        &opcode_interpreter::exec_inn_extend8_s,
        &opcode_interpreter::exec_inn_extend16_s,
        &opcode_interpreter::exec_i64_extend32_s,
        &opcode_interpreter::exec_i64_extend_i32_sx,
        &opcode_interpreter::exec_i32_wrap_i64,

        // Float Constants and Operations
        &opcode_interpreter::exec_fnn_const,
        &opcode_interpreter::exec_fnn_eq,
        &opcode_interpreter::exec_fnn_ne,
        &opcode_interpreter::exec_fnn_lt,
        &opcode_interpreter::exec_fnn_gt,
        &opcode_interpreter::exec_fnn_le,
        &opcode_interpreter::exec_fnn_ge,
        &opcode_interpreter::exec_fnn_abs,
        &opcode_interpreter::exec_fnn_neg,
        &opcode_interpreter::exec_fnn_ceil,
        &opcode_interpreter::exec_fnn_floor,
        &opcode_interpreter::exec_fnn_trunc,
        &opcode_interpreter::exec_fnn_nearest,
        &opcode_interpreter::exec_fnn_sqrt,
        &opcode_interpreter::exec_fnn_add,
        &opcode_interpreter::exec_fnn_sub,
        &opcode_interpreter::exec_fnn_mul,
        &opcode_interpreter::exec_fnn_div,
        &opcode_interpreter::exec_fnn_min,
        &opcode_interpreter::exec_fnn_max,
        &opcode_interpreter::exec_fnn_copysign,

        // Float conversions
        &opcode_interpreter::exec_f32_convert_i32_s,
        &opcode_interpreter::exec_f32_convert_i32_u,
        &opcode_interpreter::exec_f32_convert_i64_s,
        &opcode_interpreter::exec_f32_convert_i64_u,
        &opcode_interpreter::exec_f32_demote_f64,
        &opcode_interpreter::exec_f64_convert_i32_s,
        &opcode_interpreter::exec_f64_convert_i32_u,
        &opcode_interpreter::exec_f64_convert_i64_s,
        &opcode_interpreter::exec_f64_convert_i64_u,
        &opcode_interpreter::exec_f64_promote_f32,

        // Reinterpret
        &opcode_interpreter::exec_i32_reinterpret_f32,
        &opcode_interpreter::exec_i64_reinterpret_f64,
        &opcode_interpreter::exec_f32_reinterpret_i32,
        &opcode_interpreter::exec_f64_reinterpret_i64,

        // Trunc
        &opcode_interpreter::exec_i32_trunc_f32_s,
        &opcode_interpreter::exec_i32_trunc_f32_u,
        &opcode_interpreter::exec_i32_trunc_f64_s,
        &opcode_interpreter::exec_i32_trunc_f64_u,
        &opcode_interpreter::exec_i64_trunc_f32_s,
        &opcode_interpreter::exec_i64_trunc_f32_u,
        &opcode_interpreter::exec_i64_trunc_f64_s,
        &opcode_interpreter::exec_i64_trunc_f64_u,

        // Trunc sat
        &opcode_interpreter::exec_i32_trunc_sat_f32_s,
        &opcode_interpreter::exec_i32_trunc_sat_f32_u,
        &opcode_interpreter::exec_i32_trunc_sat_f64_s,
        &opcode_interpreter::exec_i32_trunc_sat_f64_u,
        &opcode_interpreter::exec_i64_trunc_sat_f32_s,
        &opcode_interpreter::exec_i64_trunc_sat_f32_u,
        &opcode_interpreter::exec_i64_trunc_sat_f64_s,
        &opcode_interpreter::exec_i64_trunc_sat_f64_u,

        // Memory access
        &opcode_interpreter::exec_inn_load,
        &opcode_interpreter::exec_inn_store,
        &opcode_interpreter::exec_inn_load8_sx,
        &opcode_interpreter::exec_inn_load16_sx,
        &opcode_interpreter::exec_i64_load32_sx,
        &opcode_interpreter::exec_inn_store8,
        &opcode_interpreter::exec_inn_store16,
        &opcode_interpreter::exec_i64_store32,

        &opcode_interpreter::exec_fnn_load,
        &opcode_interpreter::exec_fnn_store,

        // References
        &opcode_interpreter::exec_ref_null,
        &opcode_interpreter::exec_ref_is_null,
        &opcode_interpreter::exec_ref_func,

        // Parametric
        &opcode_interpreter::exec_drop,
        &opcode_interpreter::exec_select,

        // Variable
        &opcode_interpreter::exec_local_get,
        &opcode_interpreter::exec_local_set,
        &opcode_interpreter::exec_local_tee,
        &opcode_interpreter::exec_global_get,
        &opcode_interpreter::exec_global_set,

        // Table
        &opcode_interpreter::exec_table_get,
        &opcode_interpreter::exec_table_set,
        &opcode_interpreter::exec_table_size,
        &opcode_interpreter::exec_table_grow,
        &opcode_interpreter::exec_table_fill,
        &opcode_interpreter::exec_table_copy,
        &opcode_interpreter::exec_table_init,
        &opcode_interpreter::exec_elem_drop,

        // Memory
        &opcode_interpreter::exec_memory_size,
        &opcode_interpreter::exec_memory_grow,
        &opcode_interpreter::exec_memory_fill,
        &opcode_interpreter::exec_memory_copy,
        &opcode_interpreter::exec_memory_init,
        &opcode_interpreter::exec_data_drop,

        &opcode_interpreter::exec_unreachable,
    };


private:
    Context& ctx_;
    typename Context::backend_type& backend_;
    std::array<size_t, opcode::total_size> opcode_counter_;
};


}  // namespace ligero::vm
