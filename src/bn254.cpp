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

#include <zkp/finite_field_gmp.hpp>

namespace ligero::vm::zkp {

typename bn254_gmp::value_type
bn254_gmp::modulus("21888242871839275222246405745257275088548364400416034343698204186575808495617");

typename bn254_gmp::value_type
bn254_gmp::modulus_2x("43776485743678550444492811490514550177096728800832068687396408373151616991234");

typename bn254_gmp::value_type
bn254_gmp::modulus_4x("87552971487357100888985622981029100354193457601664137374792816746303233982468");

typename bn254_gmp::value_type bn254_gmp::modulus_middle("10944121435919637611123202872628637544274182200208017171849102093287904247809");

// BN254 first primitive P-1 th root
// Use primitive root  = 7;
// BN254 second primitive P-1 th root = 7^t where t = 2^61 - 1
// `t` must be coprime to P-1 and larger than 2^28 to make sure no information leak in NTT
typename bn254_gmp::value_type
bn254_gmp::root1("1748695177688661943023146337482803886740723238769601073607632802312037301404");
typename bn254_gmp::value_type
bn254_gmp::root2("2037444462055058054189478067370099086220733342011840546702672064072905551290");

// 2^28th root of unity
size_t bn254_gmp::root1_pow2_degree = 28;
size_t bn254_gmp::root2_pow2_degree = 28;

typename bn254_gmp::value_type
bn254_gmp::montgomery_factor("67081653635985823054489041608655630077888474459951605639066367465391537520641");

typename bn254_gmp::value_type
bn254_gmp::barrett_factor("38284845454613504619394467267190322316714506535725634610690744705837986343205");

std::tuple<bn254_gmp::value_type, bn254_gmp::value_type, bn254_gmp::value_type>
bn254_gmp::generate_omegas(size_t k, size_t n) {
    assert(n == 4 * k);

    value_type w_k;
    value_type w_2k;
    value_type w_4k;

    powmod_ui(w_k,  root1, (1ul << root1_pow2_degree) / k);
    powmod_ui(w_2k, root1, (1ul << root1_pow2_degree) / (2 * k));
    powmod_ui(w_4k, root2, (1ul << root2_pow2_degree) / n);
    
    return { w_k, w_2k, w_4k };
}

void bn254_gmp::reduce(value_type& out, const value_type& x) {
    mpz_fdiv_r(out.get_mpz_t(), x.get_mpz_t(), modulus.get_mpz_t());
}

void bn254_gmp::reduce_u256(value_type& out, const value_type& x) {
    out = x;
    if (out >= modulus_4x)
        out -= modulus_4x;
    if (out >= modulus_2x)
        out -= modulus_2x;
    if (out >= modulus)
        out -= modulus;
}

void bn254_gmp::negate(value_type& out, const value_type& x) {
    assert(x < modulus);
    out = x == 0 ? x : modulus - x;
}

void bn254_gmp::invmod(typename bn254_gmp::value_type& out,
                       const typename bn254_gmp::value_type& x)
{
    assert(x < modulus);
    mpz_invert(out.get_mpz_t(), x.get_mpz_t(), modulus.get_mpz_t());
}

void bn254_gmp::addmod(typename bn254_gmp::value_type& out,
                       const typename bn254_gmp::value_type& x,
                       const typename bn254_gmp::value_type& y)
{
    out = x + y;
    if (out >= modulus)
        out -= modulus;
}

void bn254_gmp::submod(typename bn254_gmp::value_type& out,
                       const typename bn254_gmp::value_type& x,
                       const typename bn254_gmp::value_type& y)
{
    out = x - y;
    if (out < 0)
        out += modulus;
}

void bn254_gmp::mulmod(typename bn254_gmp::value_type& out,
                       const typename bn254_gmp::value_type& x,
                       const typename bn254_gmp::value_type& y)
{
    thread_local value_type z, q;

    z   = x * y;
    q   = (z * barrett_factor) >> 508;
    out = z - q * modulus;
    if (out >= modulus)
        out -= modulus;
}

void bn254_gmp::mont_mulmod(value_type& out,
                            const value_type& x,
                            const value_type& y)
{
    thread_local value_type U = x * y;

    // out = U mod 2^beta (low part)
    mpz_fdiv_r_2exp(out.get_mpz_t(), U.get_mpz_t(), 256);

    // Q = U.low * J mod 2^beta
    out *= bn254_gmp::montgomery_factor;
    mpz_fdiv_r_2exp(out.get_mpz_t(), out.get_mpz_t(), 256);

    // H = Q * p / 2^beta
    out *= bn254_gmp::modulus;
    mpz_fdiv_q_2exp(out.get_mpz_t(), out.get_mpz_t(), 256);

    mpz_fdiv_q_2exp(U.get_mpz_t(), U.get_mpz_t(), 256);
    out = U - out;

    // out = U.high - H, in [-p, p) range
    
    if (out < 0)
        out += bn254_gmp::modulus;
}

void bn254_gmp::divmod(typename bn254_gmp::value_type& out,
                       const typename bn254_gmp::value_type& x,
                       const typename bn254_gmp::value_type& y)
{
    bn254_gmp::invmod(out, y);
    bn254_gmp::mulmod(out, x, out);
}

void bn254_gmp::powmod(typename bn254_gmp::value_type& out,
                       const typename bn254_gmp::value_type& x,
                       const typename bn254_gmp::value_type& exp)
{
    mpz_powm(out.get_mpz_t(), x.get_mpz_t(), exp.get_mpz_t(), modulus.get_mpz_t());
}

void bn254_gmp::powmod_ui(typename bn254_gmp::value_type& out,
                          const typename bn254_gmp::value_type& x,
                          uint32_t exp)
{
    mpz_powm_ui(out.get_mpz_t(), x.get_mpz_t(), exp, modulus.get_mpz_t());
}


bn254_gmp operator+(const bn254_gmp& x, const bn254_gmp& y) {
    bn254_gmp z;
    bn254_gmp::addmod(z.data(), x.data(), y.data());
    return z;
}

bn254_gmp operator-(const bn254_gmp& x, const bn254_gmp& y) {
    bn254_gmp z;
    bn254_gmp::submod(z.data(), x.data(), y.data());
    return z;
}

bn254_gmp operator*(const bn254_gmp& x, const bn254_gmp& y) {
    bn254_gmp z;
    bn254_gmp::mulmod(z.data(), x.data(), y.data());
    return z;
}

bn254_gmp operator/(const bn254_gmp& x, const bn254_gmp& y) {
    bn254_gmp z;
    bn254_gmp::divmod(z.data(), x.data(), y.data());
    return z;
}

bn254_gmp operator<<(const bn254_gmp& x, size_t i) {
    return x.data() << i;
}

bn254_gmp operator>>(const bn254_gmp& x, size_t i) {
    return x.data() >> i;
}

bn254_gmp operator&(const bn254_gmp& x, int i) {
    return x.data() & i;
}

std::ostream& operator<<(std::ostream& os, const bn254_gmp& f) {
    return os << f.data();
}

}  // namespace ligero::vm::zkp

