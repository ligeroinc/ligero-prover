/*
 * Copyright (C) 2023-2025 Ligero, Inc.
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

/*
 * uint256 generic prime field definition
 */

#ifndef __LIGETRON_PRIME_FIELD_UINT256_H__
#define __LIGETRON_PRIME_FIELD_UINT256_H__

#include <ligetron/uint256_cpp.h>
#include <ligetron/ff/field_element.h>
#include <ligetron/ff/concepts.h>
#include <span>


namespace ligetron::ff {


/// Generic prime field implemented on top of uint256
template <typename Derived>
struct prime_field_uint256 {
    using storage_type = uint256;
    using boolean_type = bn254fr_class;

    static constexpr size_t num_bytes = 32;
    static constexpr size_t num_rounded_bits = 8 * num_bytes;

    virtual ~prime_field_uint256() = default;

    static void set_zero(storage_type &x) {
        x.set_u32(0);
    }

    static void set_one(storage_type &x) {
        x.set_u32(1);
    }
    
    static void add(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        auto [add_res, overflow] = add_cc(x, y);
        auto [sub_res, underflow] = sub_cc(add_res, Derived::modulus());

        bn254fr_class not_underflow;
        bn254fr_class one{1};
        submod(not_underflow, one, underflow);

        // calculate `overflow || not_uderflow` as
        // `overflow + not_uderflow - overflow * not_uderflow`
        bn254fr_class tmp1, tmp2, or_res;
        addmod(tmp1, overflow, not_underflow);
        mulmod(tmp2, overflow, not_underflow);
        submod(or_res, tmp1, tmp2);

        // we need to subtract modulus if x + y >= 2^256 (overflow)
        // or out >= m (!underflow)
        mux(out, or_res, add_res, sub_res);
    }

    static void sub(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        auto [sub_res, underflow] = sub_cc(x, y);

        // we need to add modulus if and only if a < b, i.e. underflow == 1
        bn254fr_class carry;
        auto [add_res, overflow] = add_cc(sub_res, Derived::modulus());
        mux(out, underflow, sub_res, add_res);
    }

    static void mul(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        auto mul_res = mul_wide(x, y);

        uint256 div_res_low;
        bn254fr_class div_res_high;
        mul_res.divide_qr_normalized(div_res_low,
                                     div_res_high,
                                     out,
                                     Derived::modulus());
    }

    static void div(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        storage_type y_inv;
        invmod(y_inv, y, Derived::modulus());
        mul(out, x, y_inv);
    }

    static void neg(storage_type &out, const storage_type &x) {
        mux(out, ::ligetron::eqz(x), Derived::modulus() - x, x);
    }

    static void inv(storage_type &out, const storage_type &x) {
        invmod(out, x, Derived::modulus());
    }

    static void sqr(storage_type &out, const storage_type &x) {
        mul(out, x, x);
    }

    static void powm_ui(storage_type &out,
                        const storage_type &base,
                        uint32_t exp) {
        storage_type res{1};
        storage_type cur_pow = base;

        while (exp != 0) {
            if (exp & 0x1) {
                storage_type tmp;
                mul(tmp, res, cur_pow);
                res = tmp;
            }

            exp >>= 1;
            storage_type tmp2;
            mul(tmp2, cur_pow, cur_pow);
            cur_pow = tmp2;
        }

        out = res;
    }

    static void mux(storage_type &res,
                    const boolean_type &cond,
                    const storage_type &a,
                    const storage_type &b) {
        import_u256(res, ::ligetron::mux(cond, a, b));
    }

    static void eqz(boolean_type &res, const storage_type &a) {
        ::ligetron::eqz(res, a);
    }

    static void reduce(storage_type &x) {
        uint256_wide x_wide;
        x_wide.lo = x;

        bn254fr_class div_res_high;
        uint256 div_res_low;
        uint256 out;
        x_wide.divide_qr_normalized(div_res_low,
                                    div_res_high,
                                    out,
                                    Derived::modulus());
        x = out;
    }

    static void to_bits(boolean_type *bits, const storage_type &a) {
        a.to_bits(bits);
    }

    static size_t import_u32(storage_type &x, std::span<const uint32_t> limbs) {
        std::array<bn254fr_class, UINT256_NLIMBS> bn_limbs;

        size_t full_limbs = limbs.size() / 2;

        for (size_t i = 0; i < full_limbs; ++i) {
            uint64_t u64_limb = limbs[i * 2 + 1];
            u64_limb <<= 32;
            u64_limb |= limbs[i * 2];
            bn_limbs[i].set_u64(u64_limb);
        }

        if (limbs.size() % 2 != 0) {
            // adding extra limb
            bn_limbs[full_limbs].set_u32(limbs[full_limbs * 2]);
        }

        x.set_words(bn_limbs.data());

        return std::min(limbs.size(), size_t{8});
    }

    static size_t export_u32(const storage_type &x, std::span<uint32_t> limbs) {
        std::array<bn254fr_class, UINT256_NLIMBS> bn_limbs;
        x.get_words(bn_limbs.data());

        for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
            uint64_t limb_u64 = bn_limbs[i].get_u64();
            limbs[i * 2] = limb_u64 & 0xFFFFFFFFUL;
            limbs[i * 2 + 1] = limb_u64 >> 32;
        }

        return 8;
    }

    static void import_u256(storage_type &x, const uint256 &u) {
        x = u;
    }

    static void export_u256(const storage_type &x, uint256 &u) {
        u = x;
    }

    static void print(const storage_type &x) {
        x.print();
    }
};


template <typename F>
concept HasImportU256 = requires(typename F::storage_type &x,
                                 const uint256 &u) {
    { F::import_u256(x, u) };
};

template <typename F>
concept HasExportU256 = requires(const typename F::storage_type &x,
                                 uint256 &u) {
    { F::export_u256(x, u) };
};

/// Sets p256 field element from uin256 value.
/// The uint256 value must be within the field.
template <HasImportU256 F>
inline void set_uint256(field_element<F> &out, const uint256 &x) {
    F::import_u256(out.data(), x);
}

/// Converts p256 field element to uint256 value
template <HasExportU256 F>
inline const uint256 to_uint256(const field_element<F> &x) {
    uint256 res;
    F::export_u256(x.data(), res);
    return res;
}


}


#endif // __LIGETRON_PRIME_FIELD_UINT256_H__
