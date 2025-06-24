#include <ligetron/vbn254fr_class.h>
#include <ligetron/api.h>


// C API - vbn254fr implementations
// ---------------------------------------------------------------------

vbn254fr_constant vbn254fr_constant_from_str(const char *str, int base) {
    vbn254fr_constant k;
    vbn254fr_constant_set_str(&k, str, base);
    return k;
}

void vbn254fr_mux(vbn254fr_t out,
                  const vbn254fr_t s0,
                  const vbn254fr_t a0,
                  const vbn254fr_t a1)
{
    // out = s0 * a1 + a0 - s0 * a0
    vbn254fr_t tmp;
    vbn254fr_alloc(tmp);

    vbn254fr_mulmod(tmp, s0, a0);
    vbn254fr_submod(tmp, a0, tmp);
    vbn254fr_mulmod(out, s0, a1);
    vbn254fr_addmod(out, out, tmp);

    vbn254fr_free(tmp);
}


void vbn254fr_mux2(vbn254fr_t out,
                   const vbn254fr_t s0, const vbn254fr_t s1,
                   const vbn254fr_t a0, const vbn254fr_t a1,
                   const vbn254fr_t a2, const vbn254fr_t a3)
{
    vbn254fr_t tmp1, tmp2;
    vbn254fr_alloc(tmp1);
    vbn254fr_alloc(tmp2);

    vbn254fr_mux(tmp1, s0, a0, a1);
    vbn254fr_mux(tmp2, s0, a2, a3);
    vbn254fr_mux(out, s1, tmp1, tmp2);

    vbn254fr_free(tmp1);
    vbn254fr_free(tmp2);
}

void vbn254fr_oblivious_if(vbn254fr_t out,
                           const vbn254fr_t cond, const vbn254fr_t t, const vbn254fr_t f)
{
    vbn254fr_mux(out, cond, f, t);
}

void vbn254fr_bxor(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y) {
    vbn254fr_t tmp;
    vbn254fr_constant two;

    vbn254fr_alloc(tmp);
    vbn254fr_constant_set_str(&two, "2");

    vbn254fr_mulmod(tmp, x, y);
    vbn254fr_mulmod_constant(tmp, tmp, two);
    vbn254fr_submod(tmp, y, tmp);
    vbn254fr_addmod(out, x, tmp);

    vbn254fr_free(tmp);
}

void vbn254fr_neq(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y) {
    vbn254fr_constant one;
    vbn254fr_constant_set_str(&one, "1");

    vbn254fr_bxor(out, x, y);
    vbn254fr_constant_submod(out, one, out);
}

void vbn254fr_gte(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y, size_t Bit) {

    const size_t MSB = Bit - 1;

    vbn254fr_t x_bits[Bit], y_bits[Bit];

    for (int i = 0; i < Bit; i++) {
        vbn254fr_alloc(x_bits[i]);
        vbn254fr_alloc(y_bits[i]);
    }

    vbn254fr_bit_decompose(x_bits, x);
    vbn254fr_bit_decompose(y_bits, y);

    vbn254fr_t acc, iacc;
    vbn254fr_constant one;

    vbn254fr_alloc(acc);
    vbn254fr_alloc(iacc);
    vbn254fr_constant_set_str(&one, "1");

    vbn254fr_constant_submod(acc, one, y_bits[MSB]);
    vbn254fr_mulmod(acc, x_bits[MSB], acc);

    vbn254fr_neq(iacc, x_bits[MSB], y_bits[MSB]);

    vbn254fr_t tmp;
    vbn254fr_alloc(tmp);
    for (int i = MSB - 1; i >= 0; --i) {
        // update acc
        vbn254fr_constant_submod(tmp, one, y_bits[i]);
        vbn254fr_mulmod(tmp, tmp, x_bits[i]);
        vbn254fr_mulmod(tmp, tmp, iacc);
        vbn254fr_addmod(acc, acc, tmp);

        // update iacc
        vbn254fr_neq(tmp, x_bits[i], y_bits[i]);
        vbn254fr_mulmod(iacc, iacc, tmp);
    }

    vbn254fr_addmod(out, acc, iacc);

    for (int i = 0; i < Bit; i++) {
        vbn254fr_free(x_bits[i]);
        vbn254fr_free(y_bits[i]);
    }
    vbn254fr_free(tmp);
    vbn254fr_free(acc);
    vbn254fr_free(iacc);
}

// C++ API - vbn254fr_class implementations
// ---------------------------------------------------------------------

namespace ligetron {

vbn254fr_class::vbn254fr_class() {
    vbn254fr_alloc(data_);
}

vbn254fr_class::vbn254fr_class(int i) {
    vbn254fr_alloc(data_);
    vbn254fr_set_ui_scalar(data_, i);
}

vbn254fr_class::vbn254fr_class(uint32_t i) {
    vbn254fr_alloc(data_);
    vbn254fr_set_ui_scalar(data_, i);
}

vbn254fr_class::vbn254fr_class(uint32_t* num, uint64_t len) {
    vbn254fr_alloc(data_);
    vbn254fr_set_ui(data_, num, len);
}

vbn254fr_class::vbn254fr_class(const char *str[], uint64_t len, int base) {
    vbn254fr_alloc(data_);
    vbn254fr_set_str(data_, str, len, base);
}

vbn254fr_class::vbn254fr_class(const char *str, int base) {
    vbn254fr_alloc(data_);
    vbn254fr_set_str_scalar(data_, str, base);
}

vbn254fr_class::vbn254fr_class(const unsigned char *bytes, uint64_t num_bytes, uint64_t count) {
    vbn254fr_alloc(data_);
    vbn254fr_set_bytes(data_, bytes, num_bytes, count);
}

vbn254fr_class::vbn254fr_class(const unsigned char *bytes, uint64_t num_bytes) {
    vbn254fr_alloc(data_);
    vbn254fr_set_bytes_scalar(data_, bytes, num_bytes);
}

vbn254fr_class::vbn254fr_class(const vbn254fr_t o) {
    vbn254fr_alloc(data_);
    vbn254fr_copy(data_, o);
}

vbn254fr_class::vbn254fr_class(const vbn254fr_class& o) {
    vbn254fr_alloc(data_);
    vbn254fr_copy(data_, o.data_);
}

vbn254fr_class& vbn254fr_class::operator=(const vbn254fr_t o) {
    vbn254fr_copy(data_, o);
    return *this;
}

vbn254fr_class& vbn254fr_class::operator=(const vbn254fr_class& o) {
    vbn254fr_copy(data_, o.data_);
    return *this;
}

vbn254fr_class::~vbn254fr_class() {
    vbn254fr_free(data_);
}

/* --------------- Setters --------------- */

void vbn254fr_class::set_ui(uint32_t* num, uint64_t len) {
    vbn254fr_set_ui(data_, num, len);
}

void vbn254fr_class::set_ui_scalar(uint32_t x) {
    vbn254fr_set_ui_scalar(data_, x);
}

void vbn254fr_class::set_str(const char *str[], uint64_t len, int base) {
    vbn254fr_set_str(data_, str, len, base);
}

void vbn254fr_class::set_str_scalar(const char* str, uint32_t base) {
    vbn254fr_set_str_scalar(data_, str, base);
}

void vbn254fr_class::set_bytes(const unsigned char *bytes, uint64_t num_bytes, uint64_t count) {
    vbn254fr_set_bytes(data_, bytes, num_bytes, count);
}

void vbn254fr_class::set_bytes_scalar(const unsigned char *bytes, uint64_t num_bytes) {
    vbn254fr_set_bytes_scalar(data_, bytes, num_bytes);
}

/* --------------- Misc --------------- */

uint64_t vbn254fr_class::get_size() { return vbn254fr_get_size(); }

void vbn254fr_class::print_dec() const {
    vbn254fr_print(data_, 10);
}

void vbn254fr_class::print_hex() const {
    vbn254fr_print(data_, 16);
}

void vbn254fr_class::bit_decompose(vbn254fr_class* out_arr) const {
    vbn254fr_t out_buff[254];
    for (uint32_t i = 0; i < 254; ++i) {
        // use handles from the allocated data
       out_buff[i][0] = out_arr[i].data_[0];
    }
    vbn254fr_bit_decompose(out_buff, data());
}

void vbn254fr_class::mux(vbn254fr_class& out,
                  const vbn254fr_class& s0,
                  const vbn254fr_class& a0,
                  const vbn254fr_class& a1)
{
    // out = s0 * a1 + a0 - s0 * a0
    vbn254fr_mux(out.data(), s0.data(), a0.data(), a1.data());
}

void vbn254fr_class::mux2(vbn254fr_class& out,
                   const vbn254fr_class& s0, const vbn254fr_class& s1,
                   const vbn254fr_class& a0, const vbn254fr_class& a1,
                   const vbn254fr_class& a2, const vbn254fr_class& a3)
{
    vbn254fr_mux2(out.data(), s0.data(), s1.data(),
                  a0.data(), a1.data(), a2.data(), a3.data());
}


/* --------------- Vector Arithmetic --------------- */

void addmod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b) {
    vbn254fr_addmod(out.data(), a.data(), b.data());
}

void addmod_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k) {
    vbn254fr_addmod_constant(out.data(), a.data(), k);
}

void submod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b) {
    vbn254fr_submod(out.data(), a.data(), b.data());
}

void submod_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k) {
    vbn254fr_submod_constant(out.data(), a.data(), k);
}

void constant_submod(vbn254fr_class& out, const vbn254fr_constant& k, const vbn254fr_class& a) {
    vbn254fr_constant_submod(out.data(), k, a.data());
}

void mulmod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b) {
    vbn254fr_mulmod(out.data(), a.data(), b.data());
}

void mulmod_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k) {
    vbn254fr_mulmod_constant(out.data(), a.data(), k);
}

void mont_mul_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k) {
    vbn254fr_mont_mul_constant(out.data(), a.data(), k);
}

void divmod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b) {
    vbn254fr_divmod(out.data(), a.data(), b.data());
}

/* --------------- Misc --------------- */

void assert_equal(const vbn254fr_class& a, const vbn254fr_class& b) {
    vbn254fr_assert_equal(a.data(), b.data());
}

void oblivious_if(vbn254fr_class& out,
                           const vbn254fr_class& cond, const vbn254fr_class& t, const vbn254fr_class& f)
{
    vbn254fr_class::mux(out, cond, t, f);
}

} // namespace ligetron
