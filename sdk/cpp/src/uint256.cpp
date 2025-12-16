/// uint256 implementation

#include <ligetron/uint256.h>
#include <ligetron/api.h>

static constexpr size_t uint256_nbits = 64;


/// Helper class for automatic allocation and deallocation of bn254 values
class bn254fr_value {
public:
    bn254fr_value() {
        bn254fr_alloc(data_);
    }

    ~bn254fr_value() {
        bn254fr_free(data_);
    }

    __bn254fr* data() {
        return data_;
    }

private:
    bn254fr_t data_;
};

/// Helper class for uint32 constants represented as bn254 values
template <uint32_t N>
class bn254fr_const_value: public bn254fr_value {
public:
    bn254fr_const_value() {
        bn254fr_set_u32(data(), N);
    }
};

template <uint32_t N>
static inline bn254fr_const_value<N> bn254fr_const;

/// Helper class for 2^N (1<<N) bn254 const values
template <uint32_t N>
class bn254fr_power_of_2_value: public bn254fr_value {
public:
    bn254fr_power_of_2_value() {
        bn254fr_shlmod(data(),
                       bn254fr_const<1>.data(),
                       bn254fr_const<N>.data());
    }
};

template <uint32_t N>
static inline bn254fr_power_of_2_value<N> bn254fr_power_of_2;

/// Helper class for 2^N-1 (all N bits set) bn254 const values
template <uint32_t N>
class bn254fr_all_bits_value: public bn254fr_value {
public:
    bn254fr_all_bits_value() {
        bn254fr_submod(data(),
                       bn254fr_power_of_2<N>.data(),
                       bn254fr_const<1>.data());
    }
};

template <uint32_t N>
static inline bn254fr_all_bits_value<N> bn254fr_all_bits;


// Decomposes bn254 value into bits with constraints and deallocates result.
// This is used for checking that value fits in specified number of bits.
template <size_t NBits>
void check_bits(const bn254fr_t in) {
    // allocate array if bits
    bn254fr_t bits[NBits];
    for (size_t i = 0; i < NBits; ++i) {
        bn254fr_alloc(bits[i]);
    }

    // decompose value into bits and add constraints
    bn254fr_to_bits_checked(bits, in, NBits);

    // deallocate bits
    for (size_t i = 0; i < NBits; ++i) {
        bn254fr_free(bits[i]);
    }
}

void uint256_assert_equal(const uint256_t a, const uint256_t b) {
    for (size_t i = 0; i < UINT256_NLIMBS; i++) {
        bn254fr_assert_equal(a->limbs[i], b->limbs[i]);
    };
}

void uint256_alloc(uint256_t x) {
    for (size_t i = 0; i < UINT256_NLIMBS; i++) {
        bn254fr_alloc(x->limbs[i]);
    }
}

void uint256_free(uint256_t x) {
    for (size_t i = 0; i < UINT256_NLIMBS; i++) {
        bn254fr_free(x->limbs[i]);
    }
}

void uint256_set_u32(uint256_t out, uint32_t x) {
    bn254fr_set_u32(out->limbs[0], x);

    for (size_t i = 1; i < UINT256_NLIMBS; i++) {
        bn254fr_set_u32(out->limbs[i], 0);
    }
}

void uint256_set_u64(uint256_t out, uint64_t x) {
    bn254fr_set_u64(out->limbs[0], x);

    for (size_t i = 1; i < UINT256_NLIMBS; i++) {
        bn254fr_set_u32(out->limbs[i], 0);
    }
}

void uint256_set_bn254_checked(uint256_t out, const bn254fr_t x) {
    bn254fr_t zero;
    bn254fr_alloc(zero);

    bn254fr_t words[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    bn254fr_copy(words[0], x);
    uint256_set_words_checked(out, words);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }

    bn254fr_free(zero);
}


void uint256_set_bytes_little_checked(uint256_t out,
                                      const unsigned char *bytes,
                                      uint32_t len) {
    static_assert(uint256_nbits % 8 == 0 &&
                  "only uint256_nbits multiply of 8 is supported");
    constexpr auto uint256_nbytes = uint256_nbits / 8;

    bn254fr_t words[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    size_t n_full_words = len / uint256_nbytes;
    for (size_t i = 0; i < n_full_words; ++i) {
        bn254fr_set_bytes_checked(words[i],
                                  bytes + i * uint256_nbytes,
                                  uint256_nbytes,
                                  -1);
    }

    if (len % uint256_nbytes != 0) {
        bn254fr_set_bytes_checked(words[n_full_words],
                                  bytes + n_full_words * uint256_nbytes,
                                  len % uint256_nbytes,
                                  -1);
    }

    uint256_set_words_checked(out, words);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }
}


void uint256_set_bytes_big_checked(uint256_t out,
                                   const unsigned char *bytes,
                                   uint32_t len) {
    static_assert(uint256_nbits % 8 == 0 &&
                  "only uint256_nbits multiply of 8 is supported");
    constexpr auto uint256_nbytes = uint256_nbits / 8;

    bn254fr_t words[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    size_t n_full_words = len / uint256_nbytes;
    size_t extra_word_size = len % uint256_nbytes;
    if (extra_word_size != 0) {
        bn254fr_set_bytes_checked(words[n_full_words],
                                  bytes,
                                  extra_word_size,
                                  1);
    }

    for (size_t i = 0; i < n_full_words; ++i) {
        bn254fr_set_bytes_checked(words[n_full_words - i - 1],
                                  bytes + i * uint256_nbytes + extra_word_size,
                                  uint256_nbytes,
                                  1);
    }

    uint256_set_words_checked(out, words);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }
}


void uint256_set_words_checked(uint256_t out, bn254fr_t words[UINT256_NLIMBS]) {
    for (size_t i = 0; i < UINT256_NLIMBS; i++) {
        bn254fr_copy(out->limbs[i], words[i]);
        bn254fr_assert_equal(out->limbs[i], words[i]);
        check_bits<uint256_nbits>(out->limbs[i]);
    }
}

void uint256_get_words_checked(bn254fr_t words[UINT256_NLIMBS],
                               const uint256_t in) {

    for (size_t i = 0; i < UINT256_NLIMBS; i++) {
        bn254fr_copy(words[i], in->limbs[i]);
        bn254fr_assert_equal(words[i], in->limbs[i]);
    }
}

void uint256_to_bits(bn254fr_t out[256], const uint256_t in) {
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_to_bits_checked(&out[i * uint256_nbits],
                                in->limbs[i],
                                uint256_nbits);
    }
}

void uint256_from_bits(uint256_t out, const bn254fr_t in[256]) {
    bn254fr_t words[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_from_bits_checked(words[i], &in[i * uint256_nbits], 64);
    }

    uint256_set_words_checked(out, words);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }
}

uint64_t uint256_get_u64(uint256_t x) {
    return bn254fr_get_u64(x->limbs[0]);
}

void uint256_copy_checked(uint256_t dest, const uint256_t src) {
    for (size_t i = 0; i < UINT256_NLIMBS; i++) {
        bn254fr_copy(dest->limbs[i], src->limbs[i]);
        bn254fr_assert_equal(src->limbs[i], dest->limbs[i]);
    }
}

void uint256_to_bytes(unsigned char *out, uint256_t x, int order) {
    if (order == -1) {
        uint256_to_bytes_little(out, x);
    } else {
        uint256_to_bytes_big(out, x);
    }
}

void uint256_to_bytes_little(unsigned char *out, uint256_t x) {
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_to_bytes(out + i * 8, x->limbs[i], 8, -1);
    }
}

void uint256_to_bytes_big(unsigned char *out, uint256_t x) {
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_to_bytes(out + i * 8, x->limbs[UINT256_NLIMBS - i - 1], 8, 1);
    }
}

void uint256_to_bytes_checked(unsigned char *out, uint256_t x, int order) {
    if (order == -1) {
        uint256_to_bytes_little_checked(out, x);
    } else {
        uint256_to_bytes_big_checked(out, x);
    }
}

void uint256_to_bytes_little_checked(unsigned char *out, uint256_t x) {
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_to_bytes_checked(out + i * 8, x->limbs[i], 8, -1);
    }
}

void uint256_to_bytes_big_checked(unsigned char *out, uint256_t x) {
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_to_bytes_checked(out + i * 8, x->limbs[UINT256_NLIMBS - i - 1], 8, 1);
    }
}

/// Calculates sum of two bn254 values with carry bit, adds constraints
template <size_t Bits>
void bn254fr_add_checked_with_carry(bn254fr_t out,
                                    bn254fr_t carry,
                                    const bn254fr_t a,
                                    const bn254fr_t b) {
    // calculating simple bn254 sum without taking into account carry
    bn254fr_t sum;
    bn254fr_alloc(sum);
    bn254fr_addmod(sum, a, b);
    bn254fr_assert_add(sum, a, b);

    // decomposing sum into Bits+1 bits
    
    bn254fr_t bits[Bits + 1];
    for (size_t i = 0; i < Bits + 1; i++) {
        bn254fr_alloc(bits[i]);
    }

    bn254fr_to_bits_checked(bits, sum, Bits + 1);

    // copying most significant bit to carry flag
    bn254fr_copy(carry, bits[Bits]);
    bn254fr_assert_equal(carry, bits[Bits]);

    // composing all bits except of most significant one into result
    bn254fr_from_bits_checked(out, bits, Bits);

    // freeing bit values used for carry flag caclulation
    for (size_t i = 0; i < Bits + 1; i++) {
        bn254fr_free(bits[i]);
    }

    bn254fr_free(sum);
}

/// Calculates sum of three bn254 values with 1-bit carry, adds constraints.
/// The third value, c, must be a single bit.
template <size_t Bits>
void bn254fr_add_3_checked_with_carry(bn254fr_t out,
                                      bn254fr_t carry,
                                      const bn254fr_t a,
                                      const bn254fr_t b,
                                      const bn254fr_t c) {
    // calculating simple bn254 sum without taking into account carry
    bn254fr_t sum;
    bn254fr_alloc(sum);
    {
        bn254fr_t tmp;
        bn254fr_alloc(tmp);
        bn254fr_addmod_checked(tmp, a, b);
        bn254fr_addmod_checked(sum, tmp, c);
        bn254fr_free(tmp);
    }

    // decomposing sum into Bits+1 bits
    
    bn254fr_t bits[Bits + 1];
    for (size_t i = 0; i < Bits + 1; i++) {
        bn254fr_alloc(bits[i]);
    }

    bn254fr_to_bits_checked(bits, sum, Bits + 1);

    // copying most significant bit into carry
    bn254fr_from_bits_checked(carry, bits + Bits, 1);

    // composing all bits except of most significant bits into result
    bn254fr_from_bits_checked(out, bits, Bits);

    // freeing bit values used for bits
    for (size_t i = 0; i < Bits + 1; i++) {
        bn254fr_free(bits[i]);
    }

    bn254fr_free(sum);
}

/// Calculates sum of two big integers represented as arrays of bn254 libs,
/// with adding constraints
template <size_t NBits, size_t NLimbs>
void bn254fr_bigint_add_checked(bn254fr_t out[NLimbs + 1],
                                const bn254fr_t a[NLimbs],
                                const bn254fr_t b[NLimbs]) {
    // calculating sum and carry for first limbs
    bn254fr_t curr_carry;
    bn254fr_alloc(curr_carry);
    bn254fr_add_checked_with_carry<NBits>(out[0],
                                          curr_carry,
                                          a[0],
                                          b[0]);

    // calculating sum of other limbs taking into account carry calculated
    // on previous step
    for (size_t i = 1; i < NLimbs; ++i) {
        bn254fr_t new_carry;
        bn254fr_alloc(new_carry);

        bn254fr_add_3_checked_with_carry<NBits>(out[i],
                                                new_carry,
                                                a[i],
                                                b[i],
                                                curr_carry);

        // deallocating curr_carry and moving new_carry handle to it
        bn254fr_free(curr_carry);
        curr_carry[0] = new_carry[0];
    }

    // copying last curr_carry value to high limb
    bn254fr_copy(out[NLimbs], curr_carry);
    bn254fr_assert_equal(out[NLimbs], curr_carry);

    bn254fr_free(curr_carry);
}

void uint256_add_checked(uint256_t out,
                         bn254fr_t carry,
                         const uint256_t a,
                         const uint256_t b) {

    // calculating big integer sum using handles from out and carry as output
    bn254fr_t bigint_out[UINT256_NLIMBS + 1];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bigint_out[i][0] = out->limbs[i][0];
    }

    bigint_out[UINT256_NLIMBS][0] = carry[0];

    bn254fr_bigint_add_checked<uint256_nbits, UINT256_NLIMBS>(bigint_out,
                                                              a->limbs,
                                                              b->limbs);
}

template <size_t Bits>
void bn254fr_lt_checked(bn254fr_t out,
                        const bn254fr_t a,
                        const bn254fr_t b) {

    // calculating x = 2^Bits + a - b;
    bn254fr_t x;
    bn254fr_alloc(x);
    {
        bn254fr_t n_bits, bits_pow, add_res;
        bn254fr_alloc(n_bits);
        bn254fr_alloc(bits_pow);
        bn254fr_alloc(add_res);

        bn254fr_set_u32(bits_pow, static_cast<uint32_t>(1U));
        bn254fr_set_u32(n_bits, static_cast<uint32_t>(Bits));
        bn254fr_shlmod(bits_pow, bits_pow, n_bits);
        bn254fr_addmod_checked(add_res, bits_pow, a);
        bn254fr_submod_checked(x, add_res, b);

        bn254fr_free(n_bits);
        bn254fr_free(bits_pow);
        bn254fr_free(add_res);
    }

    // decomposing x into Bits+1 bits

    bn254fr_t bits[Bits + 1];
    for (size_t i = 0; i < Bits + 1; i++) {
        bn254fr_alloc(bits[i]);
    }

    bn254fr_to_bits_checked(bits, x, Bits + 1);
    bn254fr_free(x);

    // the result of comparison 1 - msb(x)
    {
        bn254fr_t one;
        bn254fr_alloc(one);
        bn254fr_set_u32(one, static_cast<uint32_t>(1));
        bn254fr_submod_checked(out, one, bits[Bits]);
        bn254fr_free(one);
    }

    for (size_t i = 0; i < Bits + 1; i++) {
        bn254fr_free(bits[i]);
    }
}

void bn254fr_eqz_checked(bn254fr_t out, const bn254fr_t x) {
    bn254fr_t inv;
    bn254fr_alloc(inv);

    if (!bn254fr_eqz(x)) {
        // inv = 1 / x
        bn254fr_invmod(inv, x);
    } else {
        // inv = 0
    }

    // out = -x * inv + 1
    {
        bn254fr_t mul_res;
        bn254fr_t neg_res;

        bn254fr_alloc(mul_res);
        bn254fr_alloc(neg_res);

        bn254fr_negmod_checked(neg_res, x);
        bn254fr_mulmod_checked(mul_res, neg_res, inv);
        bn254fr_addmod_checked(out, mul_res, bn254fr_const<1>.data());

        bn254fr_free(mul_res);
        bn254fr_free(neg_res);
    }
    
    bn254fr_free(inv);

    // checking in * out === 0
    {
        bn254fr_t mul_res;
        bn254fr_alloc(mul_res);
        bn254fr_mulmod_checked(mul_res, x, out);
        bn254fr_assert_equal(mul_res, bn254fr_const<0>.data());
        bn254fr_free(mul_res);
    }
}

void bn254fr_eq_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b) {
    bn254fr_t sub_res;
    bn254fr_alloc(sub_res);

    bn254fr_submod_checked(sub_res, a, b);
    bn254fr_eqz_checked(out, sub_res);

    bn254fr_free(sub_res);
}

/// Computes logical AND for two single-bit bn254 values, which must be either 0 or 1.
void bn254fr_land_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b) {
    bn254fr_mulmod_checked(out, a, b);
}

/// Computes logical OR for two single-bit bn254 values, which must be either 0 or 1.
void bn254fr_lor_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b) {
    // out = a + b - a * b

    bn254fr_t mul_res, add_res;
    bn254fr_alloc(mul_res);
    bn254fr_alloc(add_res);

    bn254fr_mulmod_checked(mul_res, a, b);
    bn254fr_addmod_checked(add_res, a, b);
    bn254fr_submod_checked(out, add_res, mul_res);

    bn254fr_free(mul_res);
    bn254fr_free(add_res);
}

template <size_t Bits>
void bn254fr_sub_checked_with_borrow(bn254fr_t out,
                                     bn254fr_t borrow,
                                     const bn254fr_t a,
                                     const bn254fr_t b) {

    bn254fr_t mul_res;
    bn254fr_t a_minus_b;
    bn254fr_t sum;
    bn254fr_t sum_bits[Bits + 1];

    bn254fr_alloc(mul_res);
    bn254fr_alloc(a_minus_b);
    bn254fr_alloc(sum);

    for (size_t i = 0; i < Bits + 1; ++i) {
        bn254fr_alloc(sum_bits[i]);
    }

    // a_minus_b = a - b
    bn254fr_submod_checked(a_minus_b, a, b);

    // sum = (1 << Bits) + a - b
    bn254fr_addmod(sum, bn254fr_power_of_2<Bits>.data(), a_minus_b);

    // decompose (1 << Bits) + a - b into bits
    bn254fr_to_bits(sum_bits, sum, Bits + 1);

    // borrow value is the ~msb of (1 << Bits) + a - b (result of a < b comparison)
    bn254fr_submod_checked(borrow, bn254fr_const<1>.data(), sum_bits[Bits]);

    // out is the composition of bits except of msb
    bn254fr_from_bits(out, sum_bits, Bits);

    bn254fr_free(mul_res);
    bn254fr_free(a_minus_b);
    bn254fr_free(sum);

    for (size_t i = 0; i < Bits + 1; ++i) {
        bn254fr_free(sum_bits[i]);
    }
}

// calculates a - b - c with borrow and adding constraints
template <size_t Bits>
void bn254fr_sub_3_checked_with_borrow(bn254fr_t out,
                                       bn254fr_t borrow,
                                       const bn254fr_t a,
                                       const bn254fr_t b,
                                       const bn254fr_t c) {
    bn254fr_t b_plus_c;
    bn254fr_t a_minus_b_plus_c;
    bn254fr_t sum;
    bn254fr_t sum_bits[Bits + 1];

    bn254fr_alloc(b_plus_c);
    bn254fr_alloc(a_minus_b_plus_c);
    bn254fr_alloc(sum);

    for (size_t i = 0; i < Bits + 1; ++i) {
        bn254fr_alloc(sum_bits[i]);
    }

    // b_plus_c = b + c
    bn254fr_addmod_checked(b_plus_c, b, c);

    // a_minus_b_plus_c = a - (b + c)
    bn254fr_submod_checked(a_minus_b_plus_c, a, b_plus_c);

    // sum = (1 << Bits) + a - (b + c)
    bn254fr_addmod_checked(sum,
                           bn254fr_power_of_2<Bits>.data(),
                           a_minus_b_plus_c);

    bn254fr_to_bits_checked(sum_bits, sum, Bits + 1);

    // borrow value is the msb of (1 << Bits) + a - (b + c)
    bn254fr_submod_checked(borrow, bn254fr_const<1>.data(), sum_bits[Bits]);

    // out is the composition of bits except of msb
    bn254fr_from_bits(out, sum_bits, Bits);

    // deallocaing all used values
    bn254fr_free(b_plus_c);
    bn254fr_free(a_minus_b_plus_c);
    bn254fr_free(sum);

    for (size_t i = 0; i < Bits + 1; ++i) {
        bn254fr_free(sum_bits[i]);
    }
}

void uint256_sub_checked(uint256_t out,
                         bn254fr_t underflow,
                         const uint256_t a,
                         const uint256_t b) {

    // calculating difference and borrow for first two limbs
    bn254fr_t curr_borrow;
    bn254fr_alloc(curr_borrow);
    bn254fr_sub_checked_with_borrow<uint256_nbits>(out->limbs[0],
                                                   curr_borrow,
                                                   a->limbs[0],
                                                   b->limbs[0]);

    // calculating difference of other libs taking into account borrow
    // calculated on previous step
    for (size_t i = 1; i < UINT256_NLIMBS; ++i) {
        bn254fr_t new_borrow;
        bn254fr_alloc(new_borrow);

        bn254fr_sub_3_checked_with_borrow<uint256_nbits>(out->limbs[i],
                                                         new_borrow,
                                                         a->limbs[i],
                                                         b->limbs[i],
                                                         curr_borrow);

        // deallocating curr_borrow and moving new_borrow handle to it
        bn254fr_free(curr_borrow);
        curr_borrow[0] = new_borrow[0];
    }

    // copying last curr_borrow value to resulting underflow
    bn254fr_copy(underflow, curr_borrow);
    bn254fr_assert_equal(underflow, curr_borrow);

    bn254fr_free(curr_borrow);
}

// Splits bn254 value into two N-bit and M-bit values
template <uint32_t N, uint32_t M>
void split_bn254(bn254fr_t out_1, bn254fr_t out_2, bn254fr_t in) {
    // out[0] = in % (1 << N)
    bn254fr_band(out_1, in, bn254fr_all_bits<N>.data());

    // out[1] = (in \ (1 << N)) % (1 << M)
    bn254fr_t tmp;
    bn254fr_alloc(tmp);
    bn254fr_shrmod(tmp, in, bn254fr_const<N>.data());
    bn254fr_band(out_2, tmp, bn254fr_all_bits<M>.data());
    bn254fr_free(tmp);
}

// Splits bn254 value into three N-bit, M-bit and K-bit values
template <uint32_t N, uint32_t M, uint32_t K>
void split_bn254_3(bn254fr_t out_1,
                   bn254fr_t out_2,
                   bn254fr_t out_3,
                   bn254fr_t in) {

    // out[0] = in % (1 << N)
    bn254fr_band(out_1, in, bn254fr_all_bits<N>.data());

    // out[1] = (in \ (1 << N)) % (1 << M)
    bn254fr_t tmp;
    bn254fr_alloc(tmp);
    bn254fr_shrmod(tmp, in, bn254fr_const<N>.data());
    bn254fr_band(out_2, tmp, bn254fr_all_bits<M>.data());

    // out[2] = (in \ (1 << n + m)) % (1 << k)
    bn254fr_shrmod(tmp, tmp, bn254fr_const<M>.data());
    bn254fr_band(out_3, tmp, bn254fr_all_bits<K>.data());

    bn254fr_free(tmp);
}

constexpr size_t log_ceil(size_t n) {
    size_t n_temp = n;
    for (size_t i = 0; i < 254; i++) {
        if (n_temp == 0) {
           return i;
        }
        n_temp = n_temp / 2;
    }
    return 254;
}

// Adds constraints for range check for array of bn254 original limbs
// with overflow and result limbs with carry
template <size_t NBits, size_t NLimbs>
void range_check(bn254fr_t in[NLimbs], bn254fr_t out[NLimbs + 1]) {
    // checking range of all output limbs
    for (size_t i = 0; i < NLimbs; ++i) {
        check_bits<NBits>(out[i]);
    }

    // allocate memory for running carry
    bn254fr_t running_carry[NLimbs];
    for (size_t i = 0; i < NLimbs; ++i) {
        bn254fr_alloc(running_carry[i]);
    }

    constexpr size_t n_carry_bits = NBits + log_ceil(NLimbs);

    // checking carry for the first limb
    {
        // running_carry[0] = (in[0] - out[0]) / (1 << n)
        // running_carry[0] * (1 << n) === (in[0] - out[0]);
        bn254fr_t carry_diff;
        bn254fr_alloc(carry_diff);
        bn254fr_submod_checked(carry_diff, in[0], out[0]);
        bn254fr_divmod_constant_checked(running_carry[0],
                                        carry_diff,
                                        bn254fr_power_of_2<NBits>.data());

        check_bits<n_carry_bits>(running_carry[0]);

        bn254fr_free(carry_diff);
    }

    // checking carry for other limbs
    for (size_t i = 1; i < NLimbs; ++i) {
        // We need to add the following constraint:
        // running_carry[i] = (in[i] - out[i] + running_carry[i-1]) / (1 << n);
        // running_carry[i] * (1 << n) === in[i] - out[i] + running_carry[i-1];
        //
        // To do that, we calculate running_carry[i] value with constraints

        // carry_diff = in[i] - out[i] + running_carry[i-1].
        bn254fr_t carry_diff;
        bn254fr_t tmp;
        bn254fr_alloc(carry_diff);
        bn254fr_alloc(tmp);
        bn254fr_submod_checked(tmp, in[i], out[i]);
        bn254fr_addmod_checked(carry_diff, tmp, running_carry[i - 1]);

        // running_carry[i] = carry_diff / (1 << n);
        bn254fr_divmod_constant_checked(running_carry[i],
                                        carry_diff,
                                        bn254fr_power_of_2<NBits>.data());

        // now check that running_carry[i] fits into n_carry_bits
        check_bits<n_carry_bits>(running_carry[i]);

        bn254fr_free(carry_diff);
        bn254fr_free(tmp);
    }

    // check carry for the last limb
    bn254fr_assert_equal(out[NLimbs], running_carry[NLimbs - 1]);

    for (size_t i = 0; i < NLimbs; ++i) {
        bn254fr_free(running_carry[i]);
    }
}

/// Calculates multiplication of two big integers represented
/// as array of bn254 limbs, with adding constraints
template <size_t NBits, size_t NLimbs>
void bn254fr_bigint_mul_checked(bn254fr_t out[NLimbs * 2],
                                const bn254fr_t a[NLimbs],
                                const bn254fr_t b[NLimbs]) {
    // calculating multiplication without carry

    bn254fr_t mul_no_carry_res[NLimbs * 2 - 1];
    for (size_t i = 0; i < NLimbs * 2 - 1; ++i) {
        bn254fr_alloc(mul_no_carry_res[i]);
    }

    bn254fr_bigint_mul_checked_no_carry(mul_no_carry_res, a, b, NLimbs);

    // getting proper representation for multiplication result
    bn254fr_bigint_convert_to_proper_representation(out, mul_no_carry_res,  NLimbs * 2 - 1, NBits);

    // check ranges of the result
    range_check<NBits, NLimbs * 2 - 1>(mul_no_carry_res, out);

    // deallocating temporary values
    for (size_t i = 0; i < NLimbs * 2 - 1; ++i) {
        bn254fr_free(mul_no_carry_res[i]);
    }
}

template <size_t NBits, size_t NLimbs>
void bn254fr_bigint_lt_checked(bn254fr_t out,
                               const bn254fr_t a[NLimbs],
                               const bn254fr_t b[NLimbs]) {
    static_assert(NLimbs > 2, "NLimbs > 2");

    bn254fr_t lt[NLimbs];
    bn254fr_t eq[NLimbs];

    for (size_t i = 0; i < NLimbs; ++i) {
        bn254fr_alloc(lt[i]);
        bn254fr_alloc(eq[i]);

        bn254fr_lt_checked<NBits>(lt[i], a[i], b[i]);
        bn254fr_eq_checked(eq[i], a[i], b[i]);
    }

    bn254fr_t ors[NLimbs - 1];
    bn254fr_t ands[NLimbs - 1];
    bn254fr_t eq_ands[NLimbs - 1];

    for (size_t i = 0; i < NLimbs - 1; ++i) {
        bn254fr_alloc(ors[i]);
        bn254fr_alloc(ands[i]);
        bn254fr_alloc(eq_ands[i]);
    }

    bn254fr_land_checked(ands[NLimbs - 2], eq[NLimbs - 1], lt[NLimbs - 2]);
    bn254fr_land_checked(eq_ands[NLimbs - 2], eq[NLimbs - 1], eq[NLimbs - 2]);
    bn254fr_lor_checked(ors[NLimbs - 2], lt[NLimbs - 1], ands[NLimbs - 2]);

    for (int i = NLimbs - 3; i >= 0; i--) {
        bn254fr_land_checked(ands[i], eq_ands[i + 1], lt[i]);
        bn254fr_land_checked(eq_ands[i], eq_ands[i + 1], eq[i]);
        bn254fr_lor_checked(ors[i], ors[i + 1], ands[i]);
    }

    bn254fr_copy(out, ors[0]);
    bn254fr_assert_equal(out, ors[0]);

    for (size_t i = 0; i < NLimbs; ++i) {
        bn254fr_free(lt[i]);
        bn254fr_free(eq[i]);
    }

    for (size_t i = 0; i < NLimbs - 1; ++i) {
        bn254fr_free(ors[i]);
        bn254fr_free(ands[i]);
        bn254fr_free(eq_ands[i]);
    }
}

void uint256_mul_checked(uint256_t out_low,
                         uint256_t out_high,
                         const uint256_t a,
                         const uint256_t b) {

    // calculating big integer multiplication
    // using handles from low and high results as output

    bn254fr_t out[UINT256_NLIMBS * 2];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        out[i][0] = out_low->limbs[i][0];
    }
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        out[UINT256_NLIMBS + i][0] = out_high->limbs[i][0];
    }

    bn254fr_bigint_mul_checked<uint256_nbits, UINT256_NLIMBS>(out,
                                                              a->limbs,
                                                              b->limbs);
}

void uint512_idiv_normalized_checked(uint256_t q_low,
                                     bn254fr_t q_high,
                                     uint256_t r,
                                     const uint256_t a_low,
                                     const uint256_t a_high,
                                     const uint256_t b) {
    // cacluating result of division without constraints
    uint512_idiv_normalized(q_low, q_high, r, a_low, a_high, b);

    // checking range for q_low limbs
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        check_bits<uint256_nbits>(q_low->limbs[i]);
    }

    // checking range for q_high
    check_bits<uint256_nbits>(q_high);

    // checking range for r limbs
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        check_bits<uint256_nbits>(r->limbs[i]);
    }

    // calculating multiplication q * b with constraints

    constexpr size_t mul_out_size = (UINT256_NLIMBS + 1) * 2;
    bn254fr_t mul_out[mul_out_size];
    for (size_t i = 0; i < mul_out_size; ++i) {
        bn254fr_alloc(mul_out[i]);
    }

    {
        bn254fr_t mul_q[UINT256_NLIMBS + 1];
        bn254fr_t mul_b[UINT256_NLIMBS + 1];
        for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
            mul_q[i][0] = q_low->limbs[i][0];
            mul_b[i][0] = b->limbs[i][0];
        }

        mul_q[UINT256_NLIMBS][0] = q_high[0];
        bn254fr_alloc(mul_b[UINT256_NLIMBS]);       // = 0

        bn254fr_bigint_mul_checked<uint256_nbits, UINT256_NLIMBS + 1>(mul_out,
                                                                      mul_q,
                                                                      mul_b);

        bn254fr_free(mul_b[UINT256_NLIMBS]);
    }

    // calculating q * b + r with constraints

    constexpr size_t add_arg_size = mul_out_size;
    constexpr size_t add_out_size = (UINT256_NLIMBS + 1) * 2 + 1;
    bn254fr_t add_out[add_out_size];
    for (size_t i = 0; i < add_out_size; ++i) {
        bn254fr_alloc(add_out[i]);
    }

    {
        bn254fr_t add_q_b[add_arg_size];
        bn254fr_t add_r[add_arg_size];
        
        for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
            add_q_b[i][0] = mul_out[i][0];
            add_r[i][0] = r->limbs[i][0];
        }

        for (size_t i = UINT256_NLIMBS; i < add_arg_size; ++i) {
            add_q_b[i][0] = mul_out[i][0];
        }

        for (size_t i = UINT256_NLIMBS; i < add_arg_size; ++i) {
            bn254fr_alloc(add_r[i]);     // = 0
        }

        bn254fr_bigint_add_checked<uint256_nbits, add_arg_size>(add_out,
                                                                add_q_b,
                                                                add_r);

        for (size_t i = UINT256_NLIMBS; i < add_arg_size; ++i) {
            bn254fr_free(add_r[i]);
        }
    }

    // checking q * b + r === a

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_assert_equal(add_out[i], a_low->limbs[i]);
    }

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_assert_equal(add_out[UINT256_NLIMBS + i], a_high->limbs[i]);
    }

    bn254fr_assert_equal(add_out[UINT256_NLIMBS * 2],
                         bn254fr_const<0>.data());
    bn254fr_assert_equal(add_out[UINT256_NLIMBS * 2 + 1],
                         bn254fr_const<0>.data());

    // checking r < b
    bn254fr_t lt_res;
    bn254fr_alloc(lt_res);
    bn254fr_bigint_lt_checked<uint256_nbits, UINT256_NLIMBS>(lt_res,
                                                             r->limbs,
                                                             b->limbs);
    bn254fr_assert_equal(lt_res, bn254fr_const<1>.data());
    bn254fr_free(lt_res);

    // deallocating used bn254 values

    for (size_t i = 0; i < mul_out_size; ++i) {
        bn254fr_free(mul_out[i]);
    }

    for (size_t i = 0; i < add_out_size; ++i) {
        bn254fr_free(add_out[i]);
    }
}

void uint512_mod_checked(uint256_t out,
                         const uint256_t a_low,
                         const uint256_t a_high,
                         const uint256_t m) {
    uint256_t q_low;
    bn254fr_t q_high;

    uint256_alloc(q_low);
    bn254fr_alloc(q_high);

    uint512_idiv_normalized_checked(q_low, q_high, out, a_low, a_high, m);

    uint256_free(q_low);
    bn254fr_free(q_high);
}

void uint256_eq_checked(bn254fr_t out, const uint256_t a, const uint256_t b) {
    bn254fr_t sum;
    bn254fr_alloc(sum);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        // eq = a[i] == b[i]
        bn254fr_t eq;
        bn254fr_alloc(eq);
        bn254fr_eq_checked(eq, a->limbs[i], b->limbs[i]);

        // sum += eq
        bn254fr_t tmp;
        bn254fr_alloc(tmp);
        bn254fr_addmod_checked(tmp, sum, eq);

        bn254fr_free(sum);
        sum[0] = tmp[0];        // move tmp -> sum

        bn254fr_free(eq);
    }

    // check sum == UINT256_NLIMBS
    bn254fr_eq_checked(out, sum, bn254fr_const<UINT256_NLIMBS>.data());

    bn254fr_free(sum);
}

void uint256_invmod_checked(uint256_t out, const uint256_t a, const uint256_t m) {
    uint256_t mul_low, mul_high, div_low, div_r, one, zero;
    bn254fr_t div_high;

    uint256_alloc(mul_low);
    uint256_alloc(mul_high);
    uint256_alloc(div_low);
    bn254fr_alloc(div_high);
    uint256_alloc(div_r);
    uint256_alloc(one);

    uint256_set_u32(one, 1U);

    uint256_invmod(out, a, m);
    uint256_mul_checked(mul_low, mul_high, out, a);
    uint512_idiv_normalized_checked(div_low, div_high, div_r, mul_low, mul_high, m);
    uint256_assert_equal(div_r, one);

    uint256_free(mul_low);
    uint256_free(mul_high);
    uint256_free(div_low);
    bn254fr_free(div_high);
    uint256_free(div_r);
    uint256_free(one);
}

void uint256_mux(uint256_t out,
                 const bn254fr_t cond,
                 const uint256_t a,
                 const uint256_t b) {
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_mux(out->limbs[i], cond, a->limbs[i], b->limbs[i]);
    }
}

