// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <gmpxx.h>

namespace ecdsa_r1cs {

using Big = mpz_class;

const Big& native_modulus();
Big native_reduce(const Big& value);

struct Term {
    uint32_t wire;
    Big coefficient;
};

// Terms are sorted by wire, combined, and reduced modulo the native field.
// Wire zero is the constant one. An empty combination represents zero.
class LC {
public:
    LC() = default;
    LC(long value);
    LC(const Big& value);
    explicit LC(std::vector<Term> terms);
    LC(const LC&) = default;
    LC& operator=(const LC&) = default;
    LC(LC&& other) noexcept;
    LC& operator=(LC&& other) noexcept;

    static LC wire(uint32_t index);
    std::optional<Big> constant() const;
    // Borrowed immutable view, invalidated by mutation or destruction of this
    // LC. A moved-from LC is the canonical empty combination.
    std::span<const Term> terms() const;

private:
    friend LC operator+(const LC& a, const LC& b);
    friend LC operator*(const LC& a, const Big& scalar);
    static LC canonical(std::vector<Term> terms);
    static LC single(Term term);
    // Most expressions are a single wire or constant. Inline that one Term
    // instead of allocating a vector; larger expressions retain vector storage.
    std::variant<std::vector<Term>, Term> terms_;
};

LC operator+(const LC& a, const LC& b);
LC operator-(const LC& a, const LC& b);
LC operator-(const LC& a);
LC operator*(const LC& a, const Big& scalar);
LC operator*(const Big& scalar, const LC& a);
LC operator*(const LC& a, long scalar);
LC operator*(long scalar, const LC& a);

class Builder {
public:
    enum class Mode { Checked, WitnessOnly };

    explicit Builder(std::optional<std::filesystem::path> export_prefix = {});
    // Compute auxiliary values for an independently fixed/checked circuit.
    // This mode does NOT enforce constraints or establish circuit shape. It
    // cannot export, install a row observer, or report a shape/count. Consumers
    // must enforce the original checked rows against the resulting witness.
    explicit Builder(Mode mode);
    ~Builder();
    Builder(const Builder&) = delete;
    Builder& operator=(const Builder&) = delete;

    LC input(const Big& value);
    LC witness(const Big& value);
    Big value(const LC& expression) const;
    LC mul(const LC& a, const LC& b);
    void equal(const LC& a, const LC& b);
    void constrain(const LC& a, const LC& b, const LC& c);
    std::vector<LC> bits(const LC& expression, unsigned width);
    // Identical range constraint and auxiliary wire order to bits(), without
    // retaining its bit expressions. Witness-only mode can omit construction
    // of those unused expressions; checked mode still emits every original row.
    void range_check(const LC& expression, unsigned width);

    // Capture immutable circuit rows for embedding in another proof frontend.
    // Install before the first constraint. Observing does not alter the rows,
    // public-input allocation, satisfaction checks, or shape fingerprint.
    using ConstraintObserver = std::function<void(const LC&, const LC&, const LC&)>;
    void set_constraint_observer(ConstraintObserver observer);
    // Borrowed storage, valid until the next witness allocation or destruction.
    const std::vector<Big>& witness_values() const;
    bool witness_only() const;
    // Fast-mode continuation helpers. Append contains auxiliary values only,
    // excluding wire zero and any already allocated prefix; it must not alias
    // witness_values(). Padding grows the TOTAL slot count with zeros. These
    // helpers never establish constraints and cannot be used by checked mode.
    void append_witness_values(const std::vector<Big>& values);
    void pad_witness_values(std::size_t total_variables);

    void set_stage(std::string stage);
    uint64_t constraints() const;
    uint64_t variables() const;
    uint64_t public_inputs() const;
    const std::map<std::string, uint64_t>& stage_counts() const;
    std::string shape_hash() const;

    // Writes prefix.r1cs and prefix.wtns if an export prefix was supplied.
    // No custom gates, transcript challenges, or commitment sections occur.
    void finish();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ecdsa_r1cs
