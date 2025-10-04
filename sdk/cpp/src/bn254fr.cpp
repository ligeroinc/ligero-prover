#include <ligetron/api.h>
#include <ligetron/bn254fr_class.h>

// C API - bn254fr implementations
// ---------------------------------------------------------------------

/* --------------- Scalar Initialization --------------- */

void bn254fr_set_bytes_little(bn254fr_t out, const unsigned char *bytes, uint32_t len) {
    bn254fr_set_bytes(out, bytes, len, -1);
}

void bn254fr_set_bytes_big(bn254fr_t out, const unsigned char *bytes, uint32_t len) {
    bn254fr_set_bytes(out, bytes, len, 1);
}

/* --------------- Scalar Arithmetic helpers --------------- */

void bn254fr_addmod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b) {
    bn254fr_addmod(out, a, b);
    bn254fr_assert_add(out, a, b);
}

void bn254fr_submod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b) {
    // For out = a - b, constraint: a = out + b
    bn254fr_submod(out, a, b);
    bn254fr_assert_add(a, out, b);
}

void bn254fr_negmod_checked(bn254fr_t out, const bn254fr_t a) {
    // For -a mod p, constraint: out + a = 0
    bn254fr_t zero;
    bn254fr_alloc(zero);
    bn254fr_set_u32(zero, 0);

    bn254fr_negmod(out, a);
    bn254fr_assert_add(zero, out, a);

    bn254fr_free(zero);
}

void bn254fr_mulmod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b) {
    bn254fr_mulmod(out, a, b);
    bn254fr_assert_mul(out, a, b);
}

void bn254fr_mulmod_constant_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t k) {
    bn254fr_mulmod(out, a, k);
    bn254fr_assert_mulc(out, a, k);
}

void bn254fr_divmod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b) {
    // For out = a / b, constraint: a = out * b
    bn254fr_divmod(out, a, b);
    bn254fr_assert_mul(a, out, b);
}

void bn254fr_divmod_constant_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t k) {
    bn254fr_divmod(out, a, k);
    bn254fr_assert_mulc(a, out, k);
}

void bn254fr_invmod_checked(bn254fr_t out, const bn254fr_t a) {
    // For out = a^{-1}, constraint: out * a = 1
    bn254fr_t one;
    bn254fr_alloc(one);
    bn254fr_set_u32(one, 1);

    bn254fr_invmod(out, a);
    bn254fr_assert_mul(one, out, a);

    bn254fr_free(one);
}

void bn254fr_mux(bn254fr_t out, const bn254fr_t cond, const bn254fr_t a0, const bn254fr_t a1) {
    // out = cond ? a1 : a0

    bn254fr_t tmp1, tmp2, one;
    bn254fr_alloc(one);
    bn254fr_alloc(tmp1);
    bn254fr_alloc(tmp2);

    // Assert that cond has a value of ether 0 or 1
    assert_one(bn254fr_lte(cond, one));
    bn254fr_free(one);

    // Implementing as: out = a0 + cond * (a1 - a0)
    bn254fr_submod_checked(tmp1, a1, a0);
    bn254fr_mulmod_checked(tmp2, cond, tmp1);
    bn254fr_addmod_checked(out, a0, tmp2);

    bn254fr_free(tmp1);
    bn254fr_free(tmp2);
}

void bn254fr_mux2(bn254fr_t out,
                const bn254fr_t s0, const bn254fr_t s1,
                const bn254fr_t a0, const bn254fr_t a1,
                const bn254fr_t a2, const bn254fr_t a3)
{
    bn254fr_t tmp1, tmp2, one;
    bn254fr_alloc(tmp1);
    bn254fr_alloc(tmp2);

    // Assert that cond has a value of ether 0 or 1
    assert_one(bn254fr_lte(s0, one));
    assert_one(bn254fr_lte(s1, one));
    bn254fr_free(one);

    bn254fr_mux(tmp1, s0, a0, a1);
    bn254fr_mux(tmp2, s0, a2, a3);
    bn254fr_mux(out, s1, tmp1, tmp2);

    bn254fr_free(tmp1);
    bn254fr_free(tmp2);
}

void handle_swap(bn254fr_t a, bn254fr_t b) {
    auto t = a[0].__handle;
    a[0].__handle = b[0].__handle;
    b[0].__handle = t;
}


// C++ API - bn254fr_class implementations
// ---------------------------------------------------------------------

namespace ligetron {

bn254fr_class::bn254fr_class() {
    bn254fr_alloc(data_);
}

bn254fr_class::bn254fr_class(int i) {
    bn254fr_alloc(data_);
    bn254fr_set_u32(data_, i);
}

bn254fr_class::bn254fr_class(const char *str, int base) {
    bn254fr_alloc(data_);
    bn254fr_set_str(data_, str, base);
}

bn254fr_class::bn254fr_class(const bn254fr_t o) {
    bn254fr_alloc(data_);
    bn254fr_copy(data_, o);
}

bn254fr_class::bn254fr_class(const bn254fr_class& o) {
    bn254fr_alloc(data_);
    bn254fr_copy(data_, o.data_);
    if (o.constrained_) {
        bn254fr_assert_equal(data_, o.data_);
        constrained_ = true;
    }
}

void bn254fr_class::clear() {
    if (constrained_) {
        bn254fr_free(data_);
        bn254fr_alloc(data_);
        constrained_ = false;
    }
}

bool bn254fr_class::is_constrained() const {
    return constrained_;
}

__bn254fr* bn254fr_class::clear_data() {
    clear();
    return data_;
}

const __bn254fr* bn254fr_class::data() const { return data_; }

bn254fr_class& bn254fr_class::operator=(const bn254fr_t o) {
    clear();
    bn254fr_copy(data_, o);
    return *this;
}

bn254fr_class& bn254fr_class::operator=(const bn254fr_class& o) {
    clear();
    bn254fr_copy(data_, o.data_);
    if (o.constrained_) {
        bn254fr_assert_equal(data_, o.data_);
        constrained_ = true;
    }
    return *this;
}

bn254fr_class::~bn254fr_class() { bn254fr_free(data_); }

void bn254fr_class::print_dec() const {
    bn254fr_print(data_, 10);
}

void bn254fr_class::print_hex() const {
    bn254fr_print(data_, 16);
}

uint64_t bn254fr_class::get_u64() const {
    return bn254fr_get_u64(data_);
}

/* --------------- Setters --------------- */

void bn254fr_class::set_u32(uint32_t x) {
    clear();
    bn254fr_set_u32(data_, x);
}

void bn254fr_class::set_u64(uint64_t x) {
    clear();
    bn254fr_set_u64(data_, x);
}

void bn254fr_class::set_bytes_little(const unsigned char *bytes, uint32_t len) {
    clear();
    bn254fr_set_bytes_little(data_, bytes, len);
}

void bn254fr_class::set_bytes_big(const unsigned char *bytes, uint32_t len) {
    clear();
    bn254fr_set_bytes_big(data_, bytes, len);
}

void bn254fr_class::set_str(const char* str, uint32_t base) {
    clear();
    bn254fr_set_str(data_, str, base);
}

/* ---- Scalar Comparisons ---- */

bool operator == (const bn254fr_class& a, const bn254fr_class& b) {
    return bn254fr_eq(a.data(), b.data());
}

bool operator < (const bn254fr_class& a, const bn254fr_class& b) {
    return bn254fr_lt(a.data(), b.data());
}

bool operator <= (const bn254fr_class& a, const bn254fr_class& b) {
    return bn254fr_lte(a.data(), b.data());
}

bool operator > (const bn254fr_class& a, const bn254fr_class& b) {
    return bn254fr_gt(a.data(), b.data());
}

bool operator >= (const bn254fr_class& a, const bn254fr_class& b) {
    return bn254fr_gte(a.data(), b.data());
}

bool bn254fr_class::eqz() const {
    return bn254fr_eqz(data_);
}

/* ---- Logical Operations ---- */

bool operator && (const bn254fr_class& a, const bn254fr_class& b) {
    return bn254fr_land(a.data(), b.data());
}

bool operator || (const bn254fr_class& a, const bn254fr_class& b) {
    return bn254fr_lor(a.data(), b.data());
}

/* --------------- Bitwise Operations --------------- */

void bn254fr_class::to_bits(bn254fr_class* outs, uint32_t count) {
    if ((count < 1) || (count > 254)) {
        assert_one(0);
        return;
    }

    bn254fr_t out_buff[count];
    for (uint32_t i = 0; i < count; ++i) {
        // use handles from the allocated data
       out_buff[i][0] = outs[i].data_[0];
    }

    bn254fr_to_bits_checked(out_buff, data_, count);

    for (uint32_t i = 0; i < count; ++i) {
        outs[i].constrained_ = true;
    }
    constrained_ = true;
}

void bn254fr_class::assert_equal(bn254fr_class& a, bn254fr_class& b) {
    bn254fr_assert_equal(a.data(), b.data());
    // Mark variables as constrained after assertion
    a.constrained_ = true;
    b.constrained_ = true;
}

/* --------------- Scalar Arithmetics --------------- */

#define BN254FR_UNARY(op, out, a)                         \
    do {                                                  \
        bn254fr_class tmp;                                \
        bn254fr_##op(tmp.data_, (a).data_);               \
        handle_swap(tmp.data_, (out).data_);              \
    } while (0)

#define BN254FR_BINARY(OP, OUT, A, B)                               \
    do {                                                            \
        bn254fr_class tmp;                                          \
        bn254fr_##OP(tmp.data_, (A).data_, (B).data_);              \
        handle_swap(tmp.data_, (OUT).data_);                        \
    } while (0)

void addmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b) {
    BN254FR_BINARY(addmod_checked, out, a, b);
    out.constrained_ = true;
    a.constrained_ = true;
    b.constrained_ = true;
}

void submod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b) {
    BN254FR_BINARY(submod_checked, out, a, b);
    out.constrained_ = true;
    a.constrained_ = true;
    b.constrained_ = true;
}

void mulmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b) {
    BN254FR_BINARY(mulmod_checked, out, a, b);
    out.constrained_ = true;
    a.constrained_ = true;
    b.constrained_ = true;
}

void mulmod_constant(bn254fr_class& out, bn254fr_class& a, const bn254fr_class& k) {
    BN254FR_BINARY(mulmod_constant_checked, out, a, k);
    out.constrained_ = true;
    a.constrained_ = true;
}

void divmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b) {
    BN254FR_BINARY(divmod_checked, out, a, b);
    out.constrained_ = true;
    a.constrained_ = true;
    b.constrained_ = true;
}

void divmod_constant(bn254fr_class& out, bn254fr_class& a, const bn254fr_class& k) {
    BN254FR_BINARY(divmod_constant_checked, out, a, k);
    out.constrained_ = true;
    a.constrained_ = true;
}

void negmod(bn254fr_class& out, bn254fr_class& a) {
    BN254FR_UNARY(negmod_checked, out, a);
    out.constrained_ = true;
    a.constrained_ = true;
}

void invmod(bn254fr_class& out, bn254fr_class& a) {
    BN254FR_UNARY(invmod_checked, out, a);
    out.constrained_ = true;
    a.constrained_ = true;
}

void mux_base(bn254fr_class& out, bn254fr_class& cond, bn254fr_class& a0, bn254fr_class& a1) {
    // Implementing as: out = a0 + cond * (a1 - a0)
    submod(out, a1, a0);
    mulmod(out, cond, out);
    addmod(out, a0, out);
}

void mux(bn254fr_class& out, bn254fr_class& cond, bn254fr_class& a0, bn254fr_class& a1) {
    // Assert that cond has a value of ether 0 or 1
    bn254fr_class one = 1;
    assert_one(cond <= one);

    mux_base(out, cond, a0, a1);
}

void mux2(bn254fr_class& out, bn254fr_class& s0, bn254fr_class& s1, bn254fr_class& a0, bn254fr_class& a1, bn254fr_class& a2, bn254fr_class& a3) {
    bn254fr_class one = 1;
    assert_one(s0 <= one);
    assert_one(s1 <= one);

    bn254fr_class tmp1, tmp2;
    mux(tmp1, s0, a0, a1);
    mux(tmp2, s0, a2, a3);
    mux(out, s1, tmp1, tmp2);
}

void oblivious_if(bn254fr_class& out, bool cond, bn254fr_class& t, bn254fr_class& f) {
    bn254fr_class c = (int)cond;
    mux_base(out, c, f, t);
}

} //namespace ligetron
