/*
 * uint256.h
 *
 * 256bit unsigned integer implementation
 *
 * --------------------------------------------------------------
 */

#ifndef LIGETRON_UINT256_H_
#define LIGETRON_UINT256_H_

#include "bn254fr.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <ligetron/apidef.h>
#include <ligetron/bn254fr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------- Type Definitions --------------- */

#define UINT256_NLIMBS (size_t)4

struct __uint256 {
    bn254fr_t limbs[UINT256_NLIMBS];
};

typedef struct __uint256 uint256_t[1];


/* --------------- Zero Knowledge --------------- */

/** Assert a == b (constraint only). */
void uint256_assert_equal(const uint256_t a, const uint256_t b);


/* --------------- Memory Management --------------- */

/** Allocate a new uint256 (host sets handle). */
void uint256_alloc(uint256_t x);

/** Free a previously allocated uint256. */
void uint256_free(uint256_t x);


/* --------------- Scalar Initialization --------------- */

/** Set uint256 to a uint32_t constant. */
void uint256_set_u32(uint256_t out, uint32_t x);

/** Set uint256 to a uint64_t constant. */
void uint256_set_u64(uint256_t out, uint64_t x);

/** Set uint256 from byte buffer (little-endian, up to 32 bytes mod p). */
LIGETRON_API(uint256, uint256_set_bytes_little)
void uint256_set_bytes_little(uint256_t out, const unsigned char *bytes, uint32_t len);

/** Set uint256 from byte buffer (big-endian, up to 32 bytes mod p). */
LIGETRON_API(uint256, uint256_set_bytes_big)
void uint256_set_bytes_big(uint256_t out, const unsigned char *bytes, uint32_t len);

/** Set uint256 from decimal (base=10) or hex (base=16) string. */
LIGETRON_API(uint256, uint256_set_str)
void uint256_set_str(uint256_t out, const char* str, uint32_t base);

/** Set uint256 from bn254 value, with adding constraints */
void uint256_set_bn254_checked(uint256_t out, const bn254fr_t x);

/** Set uint256 from byte buffer (little-endian, up to 32 bytes mod p).
 *  Add constraints.
 */
void uint256_set_bytes_little_checked(uint256_t out,
                                      const unsigned char *bytes,
                                      uint32_t len);

/** Set uint256 from byte buffer (big-endian, up to 32 bytes mod p).
 *  Add constraints.
 */
void uint256_set_bytes_big_checked(uint256_t out,
                                   const unsigned char *bytes,
                                   uint32_t len);


/* --------------- BN254 decomposition --------------- */

/** Set uint256 from four bn254 words, with adding constraints.
    Each word may contain up to 64 bits. */
void uint256_set_words_checked(uint256_t out,
                               bn254fr_t words[UINT256_NLIMBS]);

/** Get uint256 in four bn254 words, with adding constraints.
    Each word may contain up to 64 bits only. */
void uint256_get_words_checked(bn254fr_t words[UINT256_NLIMBS],
                               const uint256_t in);

/** Decompose uint256 into bits, with adding constraints */
void uint256_to_bits(bn254fr_t out[256], const uint256_t in);

/** Compose uint256 from bits, with adding constraints */
void uint256_from_bits(uint256_t out, const bn254fr_t in[256]);



/* --------------- Misc --------------- */

/** Get uint256 in a uint64_t constant. */
uint64_t uint256_get_u64(uint256_t x);

/** Copy uint256 from src to dest, with adding constraints. */
void uint256_copy_checked(uint256_t dest, const uint256_t src);

/** Debug print an uint256 (host decides format). */
LIGETRON_API(uint256, uint256_print)
void uint256_print(const uint256_t a);

/**
 * Convert uint256 to bytes.
 * out must point to a 32-byte length buffer.
 * "order" value:
 *   -1: use little-endian byte order,
 *    1: use big-endian byte order
 */
void uint256_to_bytes(unsigned char *out, uint256_t x, int order);

/** Convert uint256 to bytes (little-endian).
  * out must point to a 32-byte length buffer.
  */
void uint256_to_bytes_little(unsigned char *out, uint256_t x);

/** Convert uint256 to bytes (big-endian).
  * out must point to a 32-byte length buffer.
  */
void uint256_to_bytes_big(unsigned char *out, uint256_t x);

/**
 * Convert uint256 to bytes, add constraints.
 * out must point to a 32-byte length buffer.
 * "order" value:
 *   -1: use little-endian byte order,
 *    1: use big-endian byte order
 */
void uint256_to_bytes_checked(unsigned char *out, uint256_t x, int order);

/** Convert uint256 to bytes (little-endian), add constraints.
  * out must point to a 32-byte length buffer.
  */
void uint256_to_bytes_little_checked(unsigned char *out, uint256_t x);

/** Convert uint256 to bytes (big-endian), add constraints
  * out must point to a 32-byte length buffer.
  */
void uint256_to_bytes_big_checked(unsigned char *out, uint256_t x);


/* --------------- Scalar Arithmetic --------------- */

/** (out, carry) = a + b, add constraints */
void uint256_add_checked(uint256_t out,
                         bn254fr_t carry,
                         const uint256_t a,
                         const uint256_t b);

/** out = a - b, add constraints */
void uint256_sub_checked(uint256_t out,
                         bn254fr_t underflow,
                         const uint256_t a,
                         const uint256_t b);

/** (out_low, out_high) = a * b, add constraints */
void uint256_mul_checked(uint256_t out_low,
                         uint256_t out_high,
                         const uint256_t a,
                         const uint256_t b);

/** ((q_low, q_high), r) = (a_low, a_high) / b
  * Normalized uint512 division, no constraints.
  * `b` must be large enough so that its most significant
  * limb is not zero, and quotient `q` fits in
  * a uint256 and a single limb.
  */
LIGETRON_API(uint256, uint512_idiv_normalized)
void uint512_idiv_normalized(uint256_t q_low,
                             bn254fr_t q_high,
                             uint256_t r,
                             const uint256_t a_low,
                             const uint256_t a_high,
                             const uint256_t b);

/** ((q_low, q_high), r) = (a_low, a_high) / b
  * Normalized uint512 division, with constraints.
  * `b` must be large enough so that its most significant
  * limb is not zero, and quotient `q` fits in
  * a uint256 and a single limb.
  */
void uint512_idiv_normalized_checked(uint256_t q_low,
                                     bn254fr_t q_high,
                                     uint256_t r,
                                     const uint256_t a_low,
                                     const uint256_t a_high,
                                     const uint256_t b);

/** out = (a_low, a_high) mod m
  * Calculate modulus, with constraints.
  * `m` must be large enough so that its most significant
  * limb is not zero.
  */
void uint512_mod_checked(uint256_t out,
                         const uint256_t a_low,
                         const uint256_t a_high,
                         const uint256_t m);

/** out = a % b (integer remainder, add constraints) */
LIGETRON_API(uint256, uint256_irem_checked)
void uint256_irem_checked(uint256_t out, const uint256_t a, const uint256_t b);

/** out = a^-1 mod m */
LIGETRON_API(uint256, uint256_invmod)
void uint256_invmod(uint256_t out,
                    const uint256_t a,
                    const uint256_t m);

/** out = a^-1 mod m */
void uint256_invmod_checked(uint256_t out,
                            const uint256_t a,
                            const uint256_t m);


/* ---- Scalar Comparisons with constraints ---- */

/** out = a == b, with constraints */
void uint256_eq_checked(bn254fr_t out, const uint256_t a, const uint256_t b);

/** out = a < b, with constraints */
// LIGETRON_API(uint256, uint256_lt_checked)
// void uint256_lt_checked(bn254fr_t out, const uint256_t a, const uint256_t b);

// /** out = a <= b, with constraints */
// LIGETRON_API(uint256, uint256_lte_checked)
// void uint256_lte_checked(bn254fr_t out, const uint256_t a, const uint256_t b);

// /** out = a > b with constraints */
// LIGETRON_API(uint256, uint256_gt_checked)
// void uint256_gt_checked(bn254fr_t out, const uint256_t a, const uint256_t b);

// /** out = a >= b with constraints */
// LIGETRON_API(uint256, uint256_gte_checked)
// void uint256_gte_checked(bn254fr_t out, const uint256_t a, const uint256_t b);


/**
 * out = cond ? b : a
 * sets appropriate constraints
 */
 void uint256_mux(uint256_t out,
                  const bn254fr_t cond,
                  const uint256_t a,
                  const uint256_t b);


#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIGETRON_UINT256_H_
