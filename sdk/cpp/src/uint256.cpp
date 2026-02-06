/// uint256 implementation

#include <ligetron/uint256.h>
#include <ligetron/api.h>
#include <vector>


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
// n_bits must be less or equal than 256
static void check_bits(const bn254fr_t in, uint32_t n_bits) {
    // allocate array if bits
    bn254fr_t bits[256];
    for (size_t i = 0; i < n_bits; ++i) {
        bn254fr_alloc(bits[i]);
    }

    // decompose value into bits and add constraints
    bn254fr_to_bits_checked(bits, in, n_bits);

    // deallocate bits
    for (size_t i = 0; i < n_bits; ++i) {
        bn254fr_free(bits[i]);
    }
}

// Checks that bn254 value is within the (-2^(n_bits-1), 2^(n_bits-1)) range
void check_bits_signed(const bn254fr_t in, uint32_t n_bits) {
    // check that in + 2^(1 << (n_bits - 1)) has only n_bits bits

    bn254fr_t pow, n_bits_bn, sum;
    bn254fr_alloc(pow);
    bn254fr_alloc(n_bits_bn);
    bn254fr_alloc(sum);

    bn254fr_set_u32(pow, 1);
    bn254fr_set_u32(n_bits_bn, n_bits - 1);
    bn254fr_shlmod(pow, pow, n_bits_bn);
    bn254fr_addmod_checked(sum, in, pow);

    check_bits(sum, n_bits);

    bn254fr_free(pow);
    bn254fr_free(n_bits_bn);
    bn254fr_free(sum);
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
//        check_bits(out->limbs[i], uint256_nbits);
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
void bn254fr_add_checked_with_carry(bn254fr_t out,
                                    bn254fr_t carry,
                                    const bn254fr_t a,
                                    const bn254fr_t b,
                                    uint32_t n_bits) {
    // calculating simple bn254 sum without taking into account carry
    bn254fr_t sum;
    bn254fr_alloc(sum);
    bn254fr_addmod(sum, a, b);
    bn254fr_assert_add(sum, a, b);

    // decomposing sum into Bits+1 bits
    
    bn254fr_t bits[256];
    for (size_t i = 0; i < n_bits + 1; i++) {
        bn254fr_alloc(bits[i]);
    }

    bn254fr_to_bits_checked(bits, sum, n_bits + 1);

    // copying most significant bit to carry flag
    bn254fr_copy(carry, bits[n_bits]);
    bn254fr_assert_equal(carry, bits[n_bits]);

    // composing all bits except of most significant one into result
    bn254fr_from_bits_checked(out, bits, n_bits);

    // freeing bit values used for carry flag caclulation
    for (size_t i = 0; i < n_bits + 1; i++) {
        bn254fr_free(bits[i]);
    }

    bn254fr_free(sum);
}

/// Calculates sum of three bn254 values with 1-bit carry, adds constraints.
/// The third value, c, must be a single bit.
void bn254fr_add_3_checked_with_carry(bn254fr_t out,
                                      bn254fr_t carry,
                                      const bn254fr_t a,
                                      const bn254fr_t b,
                                      const bn254fr_t c,
                                      uint32_t n_bits) {
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
    
    bn254fr_t bits[256];
    for (size_t i = 0; i < n_bits + 1; i++) {
        bn254fr_alloc(bits[i]);
    }

    bn254fr_to_bits_checked(bits, sum, n_bits + 1);

    // copying most significant bit into carry
    bn254fr_from_bits_checked(carry, bits + n_bits, 1);

    // composing all bits except of most significant bits into result
    bn254fr_from_bits_checked(out, bits, n_bits);

    // freeing bit values used for bits
    for (size_t i = 0; i < n_bits + 1; i++) {
        bn254fr_free(bits[i]);
    }

    bn254fr_free(sum);
}

/// Calculates sum of two big integers represented as arrays of bn254 libs,
/// with adding constraints
void bn254fr_bigint_add_checked(bn254fr_t *out,
                                const bn254fr_t *a,
                                const bn254fr_t *b,
                                uint32_t a_count,
                                uint32_t b_count,
                                uint32_t n_bits) {
    // calculating sum and carry for first limbs
    bn254fr_t curr_carry;
    bn254fr_alloc(curr_carry);
    bn254fr_add_checked_with_carry(out[0], curr_carry, a[0], b[0], n_bits);

    uint32_t common_count = std::min(a_count, b_count);

    // calculating sum of limbs taking into account carry calculated
    // on previous step
    for (size_t i = 1; i < common_count; ++i) {
        bn254fr_t new_carry;
        bn254fr_alloc(new_carry);

        bn254fr_add_3_checked_with_carry(out[i],
                                         new_carry,
                                         a[i],
                                         b[i],
                                         curr_carry,
                                         n_bits);

        // deallocating curr_carry and moving new_carry handle to it
        bn254fr_free(curr_carry);
        curr_carry[0] = new_carry[0];
    }

    // calculating sum of extra limbs for one of operands and carry
    if (a_count > b_count) {
        for (size_t i = b_count; i < a_count; ++i) {
            bn254fr_t new_carry;
            bn254fr_alloc(new_carry);

            bn254fr_add_checked_with_carry(out[i],
                                           new_carry,
                                           a[i],
                                           curr_carry,
                                           n_bits);

            // deallocating curr_carry and moving new_carry handle to it
            bn254fr_free(curr_carry);
            curr_carry[0] = new_carry[0];
        }
    } else if (a_count < b_count) {
        for (size_t i = a_count; i < b_count; ++i) {
            bn254fr_t new_carry;
            bn254fr_alloc(new_carry);

            bn254fr_add_checked_with_carry(out[i],
                                           new_carry,
                                           b[i],
                                           curr_carry,
                                           n_bits);

            // deallocating curr_carry and moving new_carry handle to it
            bn254fr_free(curr_carry);
            curr_carry[0] = new_carry[0];
        }
    }

    // copying last curr_carry value to high limb
    auto last_idx = std::max(a_count, b_count);
    bn254fr_copy(out[last_idx], curr_carry);
    bn254fr_assert_equal(out[last_idx], curr_carry);

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

    bn254fr_bigint_add_checked(bigint_out,
                               a->limbs,
                               b->limbs,
                               UINT256_NLIMBS,
                               UINT256_NLIMBS,
                               uint256_nbits);
}

void bn254fr_sub_checked_with_borrow(bn254fr_t out,
                                     bn254fr_t borrow,
                                     const bn254fr_t a,
                                     const bn254fr_t b,
                                     uint32_t n_bits) {

    bn254fr_t mul_res;
    bn254fr_t a_minus_b;
    bn254fr_t sum;
    bn254fr_t sum_bits[256];
    bn254fr_t pow_2;
    bn254fr_t n_bits_bn;

    bn254fr_alloc(mul_res);
    bn254fr_alloc(a_minus_b);
    bn254fr_alloc(sum);
    bn254fr_alloc(pow_2);
    bn254fr_alloc(n_bits_bn);

    for (size_t i = 0; i < n_bits + 1; ++i) {
        bn254fr_alloc(sum_bits[i]);
    }

    // a_minus_b = a - b
    bn254fr_submod_checked(a_minus_b, a, b);

    // sum = (1 << Bits) + a - b
    bn254fr_set_u32(pow_2, 1);
    bn254fr_set_u32(n_bits_bn, n_bits);
    bn254fr_shlmod(pow_2, pow_2, n_bits_bn);
    bn254fr_addmod(sum, pow_2, a_minus_b);

    // decompose (1 << Bits) + a - b into bits
    bn254fr_to_bits(sum_bits, sum, n_bits + 1);

    // borrow value is the ~msb of (1 << Bits) + a - b (result of a < b comparison)
    bn254fr_submod_checked(borrow, bn254fr_const<1>.data(), sum_bits[n_bits]);

    // out is the composition of bits except of msb
    bn254fr_from_bits(out, sum_bits, n_bits);

    bn254fr_free(mul_res);
    bn254fr_free(a_minus_b);
    bn254fr_free(sum);
    bn254fr_free(pow_2);
    bn254fr_free(n_bits_bn);

    for (size_t i = 0; i < n_bits + 1; ++i) {
        bn254fr_free(sum_bits[i]);
    }
}

// calculates a - b - c with borrow and adding constraints
void bn254fr_sub_3_checked_with_borrow(bn254fr_t out,
                                       bn254fr_t borrow,
                                       const bn254fr_t a,
                                       const bn254fr_t b,
                                       const bn254fr_t c,
                                       uint32_t n_bits) {
    bn254fr_t b_plus_c;
    bn254fr_t a_minus_b_plus_c;
    bn254fr_t sum;
    bn254fr_t sum_bits[256];
    bn254fr_t pow_2;
    bn254fr_t n_bits_bn;

    bn254fr_alloc(b_plus_c);
    bn254fr_alloc(a_minus_b_plus_c);
    bn254fr_alloc(sum);
    bn254fr_alloc(pow_2);
    bn254fr_alloc(n_bits_bn);

    for (size_t i = 0; i < n_bits + 1; ++i) {
        bn254fr_alloc(sum_bits[i]);
    }

    // b_plus_c = b + c
    bn254fr_addmod_checked(b_plus_c, b, c);

    // a_minus_b_plus_c = a - (b + c)
    bn254fr_submod_checked(a_minus_b_plus_c, a, b_plus_c);

    // sum = (1 << Bits) + a - (b + c)
    bn254fr_set_u32(pow_2, 1);
    bn254fr_set_u32(n_bits_bn, n_bits);
    bn254fr_shlmod(pow_2, pow_2, n_bits_bn);
    bn254fr_addmod_checked(sum, pow_2, a_minus_b_plus_c);

    bn254fr_to_bits_checked(sum_bits, sum, n_bits + 1);

    // borrow value is the msb of (1 << Bits) + a - (b + c)
    bn254fr_submod_checked(borrow, bn254fr_const<1>.data(), sum_bits[n_bits]);

    // out is the composition of bits except of msb
    bn254fr_from_bits(out, sum_bits, n_bits);

    // deallocaing all used values
    bn254fr_free(b_plus_c);
    bn254fr_free(a_minus_b_plus_c);
    bn254fr_free(sum);
    bn254fr_free(pow_2);
    bn254fr_free(n_bits_bn);

    for (size_t i = 0; i < n_bits + 1; ++i) {
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
    bn254fr_sub_checked_with_borrow(out->limbs[0],
                                    curr_borrow,
                                    a->limbs[0],
                                    b->limbs[0],
                                    uint256_nbits);

    // calculating difference of other libs taking into account borrow
    // calculated on previous step
    for (size_t i = 1; i < UINT256_NLIMBS; ++i) {
        bn254fr_t new_borrow;
        bn254fr_alloc(new_borrow);

        bn254fr_sub_3_checked_with_borrow(out->limbs[i],
                                          new_borrow,
                                          a->limbs[i],
                                          b->limbs[i],
                                          curr_borrow,
                                          uint256_nbits);

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

constexpr uint32_t log_ceil(uint32_t n) {
    uint32_t n_temp = n;
    for (uint32_t i = 0; i < 254; i++) {
        if (n_temp == 0) {
           return i;
        }
        n_temp = n_temp / 2;
    }
    return 254;
}

// Adds constraints for range check for array of bn254 original limbs
// with overflow and result limbs with carry
void range_check(bn254fr_t *in,
                 bn254fr_t *out,
                 uint32_t count,
                 uint32_t n_bits) {
    // checking range of all output limbs
    for (size_t i = 0; i < count; ++i) {
        check_bits(out[i], n_bits);
    }

    // allocate memory for running carry
    std::vector<__bn254fr> running_carry;
    running_carry.resize(count);
    for (size_t i = 0; i < count; ++i) {
        bn254fr_alloc(&running_carry[i]);
    }

    // calculate 2^n_bits
    bn254fr_t n_bits_pow, n_bits_bn;
    bn254fr_alloc(n_bits_pow);
    bn254fr_alloc(n_bits_bn);
    bn254fr_set_u32(n_bits_pow, 2);
    bn254fr_set_u32(n_bits_bn, n_bits);
    bn254fr_powmod(n_bits_pow, n_bits_pow, n_bits_bn);

    size_t n_carry_bits = n_bits + log_ceil(count);

    // checking carry for the first limb
    {
        // running_carry[0] = (in[0] - out[0]) / (1 << n)
        // running_carry[0] * (1 << n) === (in[0] - out[0]);
        bn254fr_t carry_diff;
        bn254fr_alloc(carry_diff);
        bn254fr_submod_checked(carry_diff, in[0], out[0]);
        bn254fr_divmod_constant_checked(&running_carry[0],
                                        carry_diff,
                                        n_bits_pow);

        check_bits(&running_carry[0], n_carry_bits);

        bn254fr_free(carry_diff);
    }

    // checking carry for other limbs
    for (size_t i = 1; i < count; ++i) {
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
        bn254fr_addmod_checked(carry_diff, tmp, &running_carry[i - 1]);

        // running_carry[i] = carry_diff / (1 << n);
        bn254fr_divmod_constant_checked(&running_carry[i],
                                        carry_diff,
                                        n_bits_pow);

        // now check that running_carry[i] fits into n_carry_bits
        check_bits(&running_carry[i], n_carry_bits);

        bn254fr_free(carry_diff);
        bn254fr_free(tmp);
    }

    // check carry for the last limb
    bn254fr_assert_equal(out[count], &running_carry[count - 1]);

    for (size_t i = 0; i < count; ++i) {
        bn254fr_free(&running_carry[i]);
    }

    bn254fr_free(n_bits_bn);
    bn254fr_free(n_bits_pow);
}

// Checks that out big integer is proper representation of in big integer
void range_check_signed(const bn254fr_t *in,
                        const bn254fr_t *out,
                        uint32_t in_count,
                        uint32_t out_count,
                        uint32_t in_bits,
                        uint32_t out_bits) {
    // checking range of all output limbs
    for (size_t i = 0; i < out_count; ++i) {
        check_bits(out[i], out_bits);
    }

    bn254fr_t running_carry;
    bn254fr_alloc(running_carry);

    // calculate 2^n_bits
    bn254fr_t n_bits_pow, n_bits_bn;
    bn254fr_alloc(n_bits_pow);
    bn254fr_alloc(n_bits_bn);
    bn254fr_set_u32(n_bits_pow, 1);
    bn254fr_set_u32(n_bits_bn, out_bits);
    bn254fr_shlmod(n_bits_pow, n_bits_pow, n_bits_bn);

    size_t n_carry_bits = in_bits - out_bits + log_ceil(out_count);

    // caclulate and check carry for the first limbs
    {
        // running_carry = (out[0] - in[0]) / (1 << n)
        // running_carry * (1 << n) === (out[0] - in[0]);
        bn254fr_t carry_diff;
        bn254fr_alloc(carry_diff);
        bn254fr_submod_checked(carry_diff, out[0], in[0]);
        bn254fr_divmod_constant_checked(running_carry,
                                        carry_diff,
                                        n_bits_pow);

        // check that running carry fits into n_carry_bits bits:
        // -2^(n_carry_bits-1) <= running_carry < 2^(n_carry_bits-1)
        check_bits_signed(running_carry, n_carry_bits);
        bn254fr_free(carry_diff);
    }

    // checking carry for other limbs
    for (size_t i = 1; i < out_count; ++i) {
        // We need to add the following constraint:
        // new_running_carry = (out[i] - in[i] + running_carry) / (1 << n);
        // running_carry * (1 << n) === out[i] - in[i] + running_carry[i-1];

        // carry_diff = in[i] - out[i] + running_carry[i-1].
        bn254fr_t carry_diff;
        bn254fr_t tmp;
        bn254fr_alloc(carry_diff);
        bn254fr_alloc(tmp);

        if (i < in_count) {
            bn254fr_submod_checked(tmp, out[i], in[i]);
        } else {
            bn254fr_copy(tmp, out[i]);
            bn254fr_assert_equal(tmp, out[i]);
        }

        bn254fr_addmod_checked(carry_diff, tmp, running_carry);

        // new_running_carry = carry_diff / (1 << n);
        bn254fr_t new_running_carry;
        bn254fr_alloc(new_running_carry);
        bn254fr_divmod_constant_checked(new_running_carry,
                                        carry_diff,
                                        n_bits_pow);

        // move new_running_carry to running_carry
        bn254fr_free(running_carry);
        running_carry[0] = new_running_carry[0];

        // print_str("RUNNING CARRY[i-1]: ", 21);
        // bn254fr_print(&running_carry[i-1], 16);

        // print_str("CARRY DIFF        : ", 21);
        // bn254fr_print(carry_diff, 16);

        // print_str("RUNNING CARRY[i]:   ", 21);
        // bn254fr_print(&running_carry[i], 16);

        // check that running carry fits into n_carry_bits bits:
        // -2^(n_carry_bits-1) <= running_carry < 2^(n_carry_bits-1)
        check_bits_signed(running_carry, n_carry_bits);

        bn254fr_free(carry_diff);
        bn254fr_free(tmp);
    }

    // check that last running carry is zero
    bn254fr_assert_equal(running_carry, bn254fr_const<0>.data());

    bn254fr_free(n_bits_bn);
    bn254fr_free(n_bits_pow);
    bn254fr_free(running_carry);
}

/// Calculates number of split parts when converting to proper representation
constexpr size_t prop_rep_parts_count(size_t n_bits) {
    auto res = 256 / n_bits;
    if (256 % n_bits != 0) {
        ++res;
    }

    return res;
}

uint32_t bn254fr_bigint_mul_checked_no_carry_bits(uint32_t a_limbs,
                                                  uint32_t a_bits,
                                                  uint32_t b_limbs,
                                                  uint32_t b_bits) {
    return a_bits + b_bits + log_ceil(std::min(a_limbs, b_limbs));
}

template <size_t N>
void bn254fr_idiv_pow_2_checked(bn254fr_t q,
                                bn254fr_t r,
                                const bn254fr_t a) {
    bn254fr_t mul_res, add_res;
    bn254fr_alloc(mul_res);
    bn254fr_alloc(add_res);

    // checking q * b + r === a
    bn254fr_idiv(q, a, bn254fr_power_of_2<N>.data());
    bn254fr_irem(r, a, bn254fr_power_of_2<N>.data());
    bn254fr_mulmod_constant_checked(mul_res, q, bn254fr_power_of_2<N>.data());
    bn254fr_addmod_checked(add_res, mul_res, r);
    bn254fr_assert_equal(add_res, a);

    // checking r range
    check_bits(r, N);

    bn254fr_free(mul_res);
    bn254fr_free(add_res);
}

/// Converts big integer into proper representation with adding all
/// required constraints.
template <size_t NBits>
void bn254fr_bigint_convert_to_proper_representation_checked_complete(
        bn254fr_t *out,
        const bn254fr_t *in,
        size_t count) {

    constexpr size_t n_parts = prop_rep_parts_count(NBits);
    size_t n_out_limbs = count + prop_rep_parts_count(NBits) - 1;

    using split_t = bn254fr_t[n_parts];

    // split all limbs into parts
    split_t *splits = new split_t[count];

    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < n_parts; ++j) {
            bn254fr_alloc(splits[i][j]);
        }
    }

    for (size_t i = 0; i < count; ++i) {
        bn254fr_t limb;
        bn254fr_alloc(limb);
        bn254fr_copy(limb, in[i]);
        bn254fr_assert_equal(limb, in[i]);

        for (size_t j = 0; j < n_parts; ++j) {
            bn254fr_t tmp;
            bn254fr_alloc(tmp);
            bn254fr_idiv_pow_2_checked<NBits>(tmp,
                                              splits[i][j],
                                              limb);

            // move tmp to limb
            bn254fr_free(limb);
            limb[0] = tmp[0];
        }

        bn254fr_free(limb);
    }

    // calculate output limbs

    bn254fr_t carry;
    bn254fr_alloc(carry);

    for (size_t i = 0; i < n_out_limbs; ++i) {
        // out[i] = splits[i][0] + splits[i-1][1] + splits[i-2][2] + splits[i-3][3]

        size_t add_start_offset = 0;
        size_t add_end_offset = n_parts;

        if (i < add_end_offset - 1) {
            add_end_offset = i + 1;
        }

        if (i >= count) {
            add_start_offset = i - count + 1;
        }

        // calculate sum of splitted parts
        bn254fr_t sum;
        bn254fr_alloc(sum);
        for (size_t j = add_start_offset; j < add_end_offset; ++j) {
            bn254fr_t tmp;
            bn254fr_alloc(tmp);
            bn254fr_addmod_checked(tmp, sum, splits[i - j][j]);

            // move tmp to sum
            bn254fr_free(sum);
            sum[0] = tmp[0];
        }

        // add carry to sum
        bn254fr_t sum_with_carry;
        bn254fr_alloc(sum_with_carry);
        bn254fr_addmod_checked(sum_with_carry, sum, carry);
        bn254fr_free(sum);

        // calculate limb value and carray
        // limb[i] = sum_with_carry % 2^NBits
        // carry = sum_with_carry / 2^NBits

        bn254fr_t new_carry;
        bn254fr_alloc(new_carry);

        bn254fr_idiv_pow_2_checked<NBits>(new_carry,
                                          out[i],
                                          sum_with_carry);
        bn254fr_free(sum_with_carry);

        // move new_carry to carry
        bn254fr_free(carry);
        carry[0] = new_carry[0];
    }

    bn254fr_free(carry);

    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < n_parts; ++j) {
            bn254fr_free(splits[i][j]);
        }
    }

    delete [] splits;
}

void bn254fr_bigint_convert_to_proper_representation_signed_checked(
        bn254fr_t* out,
        const bn254fr_t* in,
        uint32_t out_count,
        uint32_t in_count,
        uint32_t out_bits,
        uint32_t in_bits) {

    bn254fr_bigint_convert_to_proper_representation_signed(out,
                                                           in,
                                                           out_count,
                                                           in_count,
                                                           out_bits);
    range_check_signed(in, out, in_count, out_count, in_bits, out_bits);
}

/// Calculates multiplication of two big integers represented
/// as arrays of bn254 limbs, with adding constraints.
void bn254fr_bigint_mul_checked(bn254fr_t *out,
                                const bn254fr_t *a,
                                const bn254fr_t *b,
                                uint32_t a_count,
                                uint32_t b_count,
                                uint32_t bits) {
    // calculating multiplication without carry

    auto mul_no_carry_res_count = a_count + b_count - 1;
    bn254fr_t *mul_no_carry_res = new bn254fr_t[a_count + b_count - 1];
    for (size_t i = 0; i < mul_no_carry_res_count; ++i) {
        bn254fr_alloc(mul_no_carry_res[i]);
    }

    bn254fr_bigint_mul_checked_no_carry(mul_no_carry_res, a, b, a_count, b_count);

    // getting proper representation for multiplication result
    bn254fr_bigint_convert_to_proper_representation(out,
                                                    mul_no_carry_res,
                                                    mul_no_carry_res_count,
                                                    bits);

    // check ranges of the result
    range_check(mul_no_carry_res, out, mul_no_carry_res_count, bits);

    // deallocating temporary values
    for (size_t i = 0; i < mul_no_carry_res_count; ++i) {
        bn254fr_free(mul_no_carry_res[i]);
    }

    delete [] mul_no_carry_res;
}

void bn254fr_bigint_lt_checked(bn254fr_t out,
                               const bn254fr_t *a,
                               const bn254fr_t *b,
                               size_t count,
                               uint32_t n_bits) {
    if (count == 1) {
        bn254fr_lt_checked(out, a[0], b[0], n_bits);
        return;
    }

    bn254fr_t *lt = new bn254fr_t[count];
    bn254fr_t *eq = new bn254fr_t[count];

    for (size_t i = 0; i < count; ++i) {
        bn254fr_alloc(lt[i]);
        bn254fr_alloc(eq[i]);

        bn254fr_lt_checked(lt[i], a[i], b[i], n_bits);
        bn254fr_eq_checked(eq[i], a[i], b[i]);
    }

    bn254fr_t *ors = new bn254fr_t[count - 1];
    bn254fr_t *ands = new bn254fr_t[count - 1];
    bn254fr_t *eq_ands = new bn254fr_t[count - 1];

    for (size_t i = 0; i < count - 1; ++i) {
        bn254fr_alloc(ors[i]);
        bn254fr_alloc(ands[i]);
        bn254fr_alloc(eq_ands[i]);
    }

    bn254fr_land_checked(ands[count - 2], eq[count - 1], lt[count - 2]);
    bn254fr_land_checked(eq_ands[count - 2], eq[count - 1], eq[count - 2]);
    bn254fr_lor_checked(ors[count - 2], lt[count - 1], ands[count - 2]);

    for (int i = count - 3; i >= 0; i--) {
        bn254fr_land_checked(ands[i], eq_ands[i + 1], lt[i]);
        bn254fr_land_checked(eq_ands[i], eq_ands[i + 1], eq[i]);
        bn254fr_lor_checked(ors[i], ors[i + 1], ands[i]);
    }

    bn254fr_copy(out, ors[0]);
    bn254fr_assert_equal(out, ors[0]);

    for (size_t i = 0; i < count; ++i) {
        bn254fr_free(lt[i]);
        bn254fr_free(eq[i]);
    }

    for (size_t i = 0; i < count - 1; ++i) {
        bn254fr_free(ors[i]);
        bn254fr_free(ands[i]);
        bn254fr_free(eq_ands[i]);
    }

    delete [] ors;
    delete [] ands;
    delete [] eq_ands;
    delete [] eq;
    delete [] lt;
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

    bn254fr_bigint_mul_checked(out,
                               a->limbs,
                               b->limbs,
                               UINT256_NLIMBS,
                               UINT256_NLIMBS,
                               uint256_nbits);
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
        check_bits(q_low->limbs[i], uint256_nbits);
    }

    // checking range for q_high
    check_bits(q_high, uint256_nbits);

    // checking range for r limbs
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        check_bits(r->limbs[i], uint256_nbits);
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

        bn254fr_bigint_mul_checked(mul_out,
                                   mul_q,
                                   mul_b,
                                   UINT256_NLIMBS + 1,
                                   UINT256_NLIMBS + 1,
                                   uint256_nbits);

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

        bn254fr_bigint_add_checked(add_out,
                                   add_q_b,
                                   add_r,
                                   add_arg_size,
                                   add_arg_size,
                                   uint256_nbits);

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
    bn254fr_bigint_lt_checked(lt_res,
                              r->limbs,
                              b->limbs,
                              UINT256_NLIMBS,
                              uint256_nbits);
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
