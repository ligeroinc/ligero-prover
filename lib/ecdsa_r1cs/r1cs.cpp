// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "r1cs.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

#include <openssl/evp.h>
#include <unistd.h>

namespace ecdsa_r1cs {
namespace {

void append_u32(std::vector<unsigned char>& out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) out.push_back((value >> (8 * i)) & 255);
}

void append_u64(std::vector<unsigned char>& out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out.push_back((value >> (8 * i)) & 255);
}

void append_field(std::vector<unsigned char>& out, const Big& value) {
    if (value < 0 || mpz_sizeinbase(value.get_mpz_t(), 2) > 256)
        throw std::runtime_error("field serialization value is outside 256 bits");
    std::array<unsigned char, 32> bytes{};
    size_t count = 0;
    mpz_export(bytes.data(), &count, -1, 1, 0, 0, value.get_mpz_t());
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_lc(std::vector<unsigned char>& out, const LC& lc) {
    if (lc.terms().size() > UINT32_MAX) throw std::runtime_error("too many LC terms");
    append_u32(out, static_cast<uint32_t>(lc.terms().size()));
    for (const auto& term : lc.terms()) {
        append_u32(out, term.wire);
        append_field(out, term.coefficient);
    }
}

void write_bytes(std::ostream& out, const std::vector<unsigned char>& bytes) {
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (!out) throw std::runtime_error("failed to write R1CS export");
}

void section(std::ostream& out, uint32_t kind, uint64_t size) {
    std::vector<unsigned char> bytes;
    append_u32(bytes, kind);
    append_u64(bytes, size);
    write_bytes(out, bytes);
}

std::filesystem::path temporary_file(const std::filesystem::path& prefix) {
    std::string pattern = prefix.string() + ".XXXXXX";
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
    int fd = mkstemp(writable.data());
    if (fd < 0) throw std::runtime_error("could not create export temporary file");
    close(fd);
    return writable.data();
}

void digest_update(EVP_MD_CTX* ctx, const void* bytes, size_t size) {
    if (EVP_DigestUpdate(ctx, bytes, size) != 1)
        throw std::runtime_error("SHA-256 update failed");
}

} // namespace

const Big& native_modulus() {
    static const Big modulus("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    return modulus;
}

Big native_reduce(const Big& value) {
    if (value >= 0 && value < native_modulus()) return value;
    Big result;
    mpz_mod(result.get_mpz_t(), value.get_mpz_t(), native_modulus().get_mpz_t());
    return result;
}

LC::LC(long value) : LC(Big(value)) {}
LC::LC(const Big& value) {
    Big reduced = native_reduce(value);
    if (reduced != 0) terms_.push_back({0, std::move(reduced)});
}

LC::LC(std::vector<Term> terms) {
    std::sort(terms.begin(), terms.end(), [](const Term& a, const Term& b) { return a.wire < b.wire; });
    for (auto& term : terms) {
        if (!terms_.empty() && terms_.back().wire == term.wire) {
            terms_.back().coefficient += term.coefficient;
        } else {
            terms_.push_back(std::move(term));
        }
    }
    for (auto& term : terms_) term.coefficient = native_reduce(term.coefficient);
    std::erase_if(terms_, [](const Term& term) { return term.coefficient == 0; });
}

LC LC::wire(uint32_t index) {
    LC result;
    result.terms_.push_back({index, Big(1)});
    return result;
}

std::optional<Big> LC::constant() const {
    if (terms_.empty()) return Big(0);
    if (terms_.size() == 1 && terms_[0].wire == 0) return terms_[0].coefficient;
    return {};
}

LC operator+(const LC& a, const LC& b) {
    // Both operands already satisfy LC's canonical invariant. Merging keeps
    // that invariant without sorting and reducing every existing coefficient
    // again (especially expensive for incrementally built lookup tables).
    LC result;
    result.terms_.reserve(a.terms_.size() + b.terms_.size());
    auto left = a.terms_.begin(), right = b.terms_.begin();
    while (left != a.terms_.end() && right != b.terms_.end()) {
        if (left->wire < right->wire) result.terms_.push_back(*left++);
        else if (right->wire < left->wire) result.terms_.push_back(*right++);
        else {
            Big coefficient = left->coefficient + right->coefficient;
            if (coefficient >= native_modulus()) coefficient -= native_modulus();
            if (coefficient != 0)
                result.terms_.push_back({left->wire, std::move(coefficient)});
            ++left;
            ++right;
        }
    }
    result.terms_.insert(result.terms_.end(), left, a.terms_.end());
    result.terms_.insert(result.terms_.end(), right, b.terms_.end());
    return result;
}

LC operator-(const LC& a, const LC& b) { return a + (-b); }
LC operator-(const LC& a) { return a * -1L; }
LC operator*(const LC& a, const Big& scalar) {
    const Big reduced = native_reduce(scalar);
    if (reduced == 0) return LC();
    if (reduced == 1) return a;
    LC result;
    result.terms_.reserve(a.terms_.size());
    const bool negate = reduced == native_modulus() - 1;
    for (const auto& term : a.terms_) {
        // A nonzero coefficient times a nonzero scalar remains nonzero in
        // this field, so scaling preserves sorted, distinct wire indices.
        Big coefficient = negate ? Big(native_modulus() - term.coefficient)
                                 : native_reduce(term.coefficient * reduced);
        result.terms_.push_back({term.wire, std::move(coefficient)});
    }
    return result;
}
LC operator*(const Big& scalar, const LC& a) { return a * scalar; }
LC operator*(const LC& a, long scalar) { return a * Big(scalar); }
LC operator*(long scalar, const LC& a) { return a * Big(scalar); }

struct Builder::Impl {
    Builder::Mode mode;
    std::optional<std::filesystem::path> prefix;
    std::filesystem::path rows_path;
    std::ofstream rows;
    std::vector<Big> values{Big(1)};
    uint64_t count = 0, public_count = 0, row_bytes = 0;
    bool auxiliary_started = false, finished = false;
    std::string stage = "unclassified";
    std::map<std::string, uint64_t> stages;
    Builder::ConstraintObserver observer;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest{nullptr, EVP_MD_CTX_free};

    explicit Impl(std::optional<std::filesystem::path> export_prefix,
                  Builder::Mode builder_mode = Builder::Mode::Checked)
        : mode(builder_mode), prefix(std::move(export_prefix)) {
        if (mode == Builder::Mode::WitnessOnly) {
            if (prefix) throw std::runtime_error("witness-only builder cannot export constraints");
            return;
        }
        digest.reset(EVP_MD_CTX_new());
        if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1)
            throw std::runtime_error("SHA-256 initialization failed");
        const std::string domain = "ecdsa_r1cs:BN254:shape:v1";
        digest_update(digest.get(), domain.data(), domain.size());
        if (prefix) {
            if (!prefix->parent_path().empty()) std::filesystem::create_directories(prefix->parent_path());
            rows_path = temporary_file(prefix->string() + ".rows");
            rows.open(rows_path, std::ios::binary | std::ios::trunc);
            if (!rows) {
                std::filesystem::remove(rows_path);
                throw std::runtime_error("could not open constraint stream");
            }
        }
    }

    ~Impl() {
        rows.close();
        if (!rows_path.empty()) {
            std::error_code ignored;
            std::filesystem::remove(rows_path, ignored);
        }
    }

    void require_open() const {
        if (finished) throw std::runtime_error("builder is already finished");
    }

    void require_checked() const {
        if (mode == Builder::Mode::WitnessOnly)
            throw std::runtime_error("witness-only builder does not establish or expose circuit shape");
    }

    LC allocate(const Big& v) {
        require_open();
        if (values.size() >= UINT32_MAX) throw std::runtime_error("R1CS wire limit exceeded");
        uint32_t index = static_cast<uint32_t>(values.size());
        values.push_back(native_reduce(v));
        return LC::wire(index);
    }
};

Builder::Builder(std::optional<std::filesystem::path> export_prefix) : impl_(std::make_unique<Impl>(std::move(export_prefix))) {}
Builder::Builder(Mode mode) : impl_(std::make_unique<Impl>(std::nullopt, mode)) {}
Builder::~Builder() = default;

LC Builder::input(const Big& v) {
    if (impl_->auxiliary_started) throw std::runtime_error("all public inputs must precede auxiliary witnesses");
    LC result = impl_->allocate(v);
    ++impl_->public_count;
    return result;
}

LC Builder::witness(const Big& v) {
    LC result = impl_->allocate(v);
    impl_->auxiliary_started = true;
    return result;
}

Big Builder::value(const LC& expression) const {
    const auto& terms = expression.terms();
    if (terms.empty()) return Big(0);
    if (terms.size() == 1) {
        const auto& term = terms.front();
        if (term.wire >= impl_->values.size()) throw std::runtime_error("linear combination uses unknown wire");
        if (term.wire == 0) return term.coefficient;
        if (term.coefficient == 1) return impl_->values[term.wire];
        return native_reduce(term.coefficient * impl_->values[term.wire]);
    }
    Big result = 0;
    for (const auto& term : terms) {
        if (term.wire >= impl_->values.size()) throw std::runtime_error("linear combination uses unknown wire");
        mpz_addmul(result.get_mpz_t(), term.coefficient.get_mpz_t(), impl_->values[term.wire].get_mpz_t());
    }
    return native_reduce(result);
}

LC Builder::mul(const LC& a, const LC& b) {
    impl_->require_open();
    if (auto constant = a.constant()) return b * *constant;
    if (auto constant = b.constant()) return a * *constant;
    LC product = witness(value(a) * value(b));
    constrain(a, b, product);
    return product;
}

void Builder::equal(const LC& a, const LC& b) {
    impl_->require_open();
    if (witness_only()) return;
    LC diff = a - b;
    if (auto constant = diff.constant(); constant && *constant == 0) return;
    constrain(diff, LC(1L), LC(0L));
}

void Builder::constrain(const LC& a, const LC& b, const LC& c) {
    impl_->require_open();
    if (witness_only()) return;
    if (native_reduce(value(a) * value(b) - value(c)) != 0)
        throw std::runtime_error("unsatisfied R1CS constraint " + std::to_string(impl_->count) + " in stage " + impl_->stage);
    if (impl_->count == UINT32_MAX) throw std::runtime_error("R1CS constraint limit exceeded");
    std::vector<unsigned char> bytes;
    bytes.reserve(12 + 36 * (a.terms().size() + b.terms().size() + c.terms().size()));
    append_lc(bytes, a);
    append_lc(bytes, b);
    append_lc(bytes, c);
    digest_update(impl_->digest.get(), bytes.data(), bytes.size());
    if (impl_->prefix) write_bytes(impl_->rows, bytes);
    impl_->row_bytes += bytes.size();
    ++impl_->count;
    ++impl_->stages[impl_->stage];
    if (impl_->observer) impl_->observer(a, b, c);
}

void Builder::set_constraint_observer(ConstraintObserver observer) {
    impl_->require_open();
    impl_->require_checked();
    if (impl_->count) throw std::runtime_error("install constraint observer before the first row");
    impl_->observer = std::move(observer);
}

const std::vector<Big>& Builder::witness_values() const { return impl_->values; }
bool Builder::witness_only() const { return impl_->mode == Mode::WitnessOnly; }

void Builder::append_witness_values(const std::vector<Big>& values) {
    impl_->require_open();
    if (!witness_only() || !impl_->public_count)
        throw std::runtime_error("witness continuation requires witness-only mode with allocated inputs");
    if (&values == &impl_->values)
        throw std::runtime_error("witness continuation cannot alias its builder");
    if (values.size() > UINT32_MAX - impl_->values.size())
        throw std::runtime_error("R1CS wire limit exceeded");
    for (const auto& value : values) {
        if (value < 0 || value >= native_modulus())
            throw std::runtime_error("witness continuation value is not a canonical native-field element");
    }
    impl_->values.insert(impl_->values.end(), values.begin(), values.end());
    impl_->auxiliary_started = true;
}

void Builder::pad_witness_values(std::size_t total_variables) {
    impl_->require_open();
    if (!witness_only() || !impl_->public_count)
        throw std::runtime_error("witness padding requires witness-only mode with allocated inputs");
    if (total_variables < impl_->values.size())
        throw std::runtime_error("witness padding cannot shrink the existing prefix");
    if (total_variables > UINT32_MAX)
        throw std::runtime_error("R1CS wire limit exceeded");
    impl_->values.resize(total_variables, Big(0));
    impl_->auxiliary_started = true;
}

std::vector<LC> Builder::bits(const LC& expression, unsigned width) {
    impl_->require_open();
    if (width > 200) throw std::runtime_error("bit decomposition width must be at most 200");
    const Big v = value(expression);
    if (v >= (Big(1) << width)) throw std::runtime_error("value does not fit requested bit width");
    std::vector<LC> result;
    result.reserve(width);
    const bool is_constant = expression.constant().has_value();
    if (witness_only()) {
        // The output wires (including allocation order) are the same. The
        // Boolean rows and reconstruction sum belong to the checked template,
        // so constructing their otherwise unused expressions is unnecessary.
        for (unsigned i = 0; i < width; ++i) {
            const Big bit = mpz_tstbit(v.get_mpz_t(), i) ? 1 : 0;
            result.push_back(is_constant ? LC(bit) : witness(bit));
        }
        return result;
    }
    LC sum;
    Big weight = 1;
    for (unsigned i = 0; i < width; ++i) {
        const Big bit = mpz_tstbit(v.get_mpz_t(), i) ? 1 : 0;
        LC wire = is_constant ? LC(bit) : witness(bit);
        if (!is_constant) constrain(wire, wire - LC(1L), LC(0L));
        sum = sum + wire * weight;
        weight <<= 1;
        result.push_back(std::move(wire));
    }
    equal(expression, sum);
    return result;
}

void Builder::set_stage(std::string stage) { impl_->require_open(); impl_->stage = std::move(stage); }
uint64_t Builder::constraints() const { impl_->require_checked(); return impl_->count; }
uint64_t Builder::variables() const { return impl_->values.size(); }
uint64_t Builder::public_inputs() const { return impl_->public_count; }
const std::map<std::string, uint64_t>& Builder::stage_counts() const { impl_->require_checked(); return impl_->stages; }

std::string Builder::shape_hash() const {
    impl_->require_checked();
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> copy(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!copy || EVP_MD_CTX_copy_ex(copy.get(), impl_->digest.get()) != 1)
        throw std::runtime_error("SHA-256 state copy failed");
    std::vector<unsigned char> header;
    append_u64(header, variables());
    append_u64(header, public_inputs());
    append_u64(header, constraints());
    digest_update(copy.get(), header.data(), header.size());
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
    unsigned length = 0;
    if (EVP_DigestFinal_ex(copy.get(), bytes.data(), &length) != 1)
        throw std::runtime_error("SHA-256 finalization failed");
    std::ostringstream result;
    for (unsigned i = 0; i < length; ++i) result << std::hex << std::setw(2) << std::setfill('0') << unsigned(bytes[i]);
    return result.str();
}

void Builder::finish() {
    if (impl_->finished) return;
    if (!impl_->prefix) { impl_->finished = true; return; }
    impl_->rows.flush();
    if (!impl_->rows) throw std::runtime_error("failed to flush constraint stream");
    impl_->rows.close();
    const auto r1cs_path = temporary_file(impl_->prefix->string() + ".r1cs");
    std::filesystem::path wtns_path;
    try {
        wtns_path = temporary_file(impl_->prefix->string() + ".wtns");
        std::ofstream out(r1cs_path, std::ios::binary | std::ios::trunc);
        out.write("r1cs", 4);
        std::vector<unsigned char> bytes;
        append_u32(bytes, 1); append_u32(bytes, 3); write_bytes(out, bytes);
        section(out, 1, 64);
        bytes.clear();
        append_u32(bytes, 32); append_field(bytes, native_modulus());
        append_u32(bytes, static_cast<uint32_t>(variables()));
        append_u32(bytes, 0); // public outputs
        append_u32(bytes, static_cast<uint32_t>(public_inputs()));
        append_u32(bytes, 0); // private input wires (all private wires are auxiliaries)
        append_u64(bytes, variables());
        append_u32(bytes, static_cast<uint32_t>(constraints()));
        write_bytes(out, bytes);
        section(out, 2, impl_->row_bytes);
        std::ifstream rows(impl_->rows_path, std::ios::binary);
        std::array<char, 1 << 16> buffer{};
        while (rows) {
            rows.read(buffer.data(), buffer.size());
            out.write(buffer.data(), rows.gcount());
        }
        if (!rows.eof() || !out) throw std::runtime_error("failed to copy constraint stream");
        section(out, 3, 8 * variables());
        for (uint64_t i = 0; i < variables(); ++i) {
            bytes.clear(); append_u64(bytes, i); write_bytes(out, bytes);
        }
        out.close();
        if (!out) throw std::runtime_error("failed to close R1CS export");

        std::ofstream witness_out(wtns_path, std::ios::binary | std::ios::trunc);
        witness_out.write("wtns", 4);
        bytes.clear(); append_u32(bytes, 2); append_u32(bytes, 2); write_bytes(witness_out, bytes);
        section(witness_out, 1, 40);
        bytes.clear(); append_u32(bytes, 32); append_field(bytes, native_modulus());
        append_u32(bytes, static_cast<uint32_t>(variables())); write_bytes(witness_out, bytes);
        section(witness_out, 2, 32 * variables());
        for (const Big& v : impl_->values) {
            bytes.clear(); append_field(bytes, v); write_bytes(witness_out, bytes);
        }
        witness_out.close();
        if (!witness_out) throw std::runtime_error("failed to close witness export");
        std::filesystem::rename(r1cs_path, impl_->prefix->string() + ".r1cs");
        std::filesystem::rename(wtns_path, impl_->prefix->string() + ".wtns");
        impl_->finished = true;
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(r1cs_path, ignored);
        if (!wtns_path.empty()) std::filesystem::remove(wtns_path, ignored);
        throw;
    }
}

} // namespace ecdsa_r1cs
