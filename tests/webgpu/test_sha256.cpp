#define BOOST_TEST_MODULE "WebGPU.sha256"
#include <boost/test/included/unit_test.hpp>

#include <array>
#include <cstdint>
#include <vector>
#include <openssl/sha.h>
#include <wgpu.hpp>
#include <zkp/finite_field_gmp.hpp>

// Check the actual shader against OpenSSL, including odd/even field counts
// (half-full/full SHA blocks) and partially populated, zero-padded rows.
BOOST_AUTO_TEST_CASE(field_updates_match_cpu_sha256)
{
    constexpr size_t instances = 257; // Also cover a partial workgroup.
    constexpr size_t limbs_per_field = 8;
    ligero::webgpu_context gpu;
    gpu.webgpu_init(256, std::filesystem::path(PROJECT_ROOT_DIR) / "shader");
    gpu.sha256_init(instances);

    auto context = gpu.make_device_buffer(instances * sizeof(ligero::webgpu_context::sha256_context));
    auto digest = gpu.make_device_buffer(instances * SHA256_DIGEST_LENGTH);
    auto input = gpu.make_device_buffer(instances * limbs_per_field * sizeof(uint32_t));
    auto bind_context = gpu.bind_sha256_context(context, digest);
    auto bind_input = gpu.bind_sha256_buffer(input);
    std::vector<uint32_t> poison(instances * limbs_per_field, 0xffffffffu);
    uint32_t random_state = 0x347a18c9u;

    for (size_t rows : {0u, 1u, 2u, 3u, 4u, 7u, 16u, 33u}) {
        gpu.sha256_digest_init(bind_context);
        std::vector<std::vector<unsigned char>> messages(instances);
        for (size_t row = 0; row < rows; ++row) {
            const std::array<size_t, 4> populated = {instances, 37, 0, instances - 1};
            const size_t active = populated[row % populated.size()];
            std::vector<uint32_t> values(instances * limbs_per_field, 0);
            for (size_t i = 0; i < active * limbs_per_field; ++i) {
                random_state ^= random_state << 13;
                random_state ^= random_state >> 17;
                random_state ^= random_state << 5;
                values[i] = random_state;
            }
            // Poison the reused buffer so a missing partial-row clear fails.
            gpu.write_buffer(input, poison.data(), poison.size());
            gpu.write_buffer_clear(input, values.data(), active * limbs_per_field);
            gpu.sha256_digest_update(bind_context, bind_input);
            for (size_t instance = 0; instance < instances; ++instance) {
                for (size_t limb = 0; limb < limbs_per_field; ++limb) {
                    const uint32_t value = values[instance * limbs_per_field + limb];
                    for (int shift : {24, 16, 8, 0}) {
                        messages[instance].push_back(static_cast<unsigned char>(value >> shift));
                    }
                }
            }
        }

        gpu.sha256_digest_final(bind_context);
        const auto actual = gpu.copy_to_host<uint32_t>(digest);
        BOOST_REQUIRE_EQUAL(actual.size(), instances * limbs_per_field);
        for (size_t instance = 0; instance < instances; ++instance) {
            std::array<unsigned char, SHA256_DIGEST_LENGTH> expected;
            SHA256(messages[instance].data(), messages[instance].size(), expected.data());
            for (size_t word = 0; word < limbs_per_field; ++word) {
                const uint32_t value = (uint32_t(expected[4 * word]) << 24)
                    | (uint32_t(expected[4 * word + 1]) << 16)
                    | (uint32_t(expected[4 * word + 2]) << 8)
                    | uint32_t(expected[4 * word + 3]);
                BOOST_CHECK_EQUAL(actual[instance * limbs_per_field + word], value);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(copy_clear_preserves_prefix_and_clears_only_view_tail)
{
    ligero::webgpu::device_context gpu;
    gpu.device_init();
    const std::array<uint32_t, 4> source = {1, 0x12345678u, 0xffffffffu, 0};
    const std::array<uint32_t, 10> poison = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
    auto from = gpu.make_device_buffer(sizeof(source));
    auto to = gpu.make_device_buffer(sizeof(poison));
    gpu.write_buffer(from, source.data(), source.size());
    for (size_t view_words : {source.size(), size_t(8)}) {
        gpu.write_buffer(to, poison.data(), poison.size());
        gpu.copy_buffer_clear(from, to.slice_bytes(sizeof(uint32_t), view_words * sizeof(uint32_t)));
        const auto actual = gpu.copy_to_host<uint32_t>(to);
        for (size_t i = 0; i < poison.size(); ++i) {
            const uint32_t expected = i == 0 || i > view_words ? 9
                : i <= source.size() ? source[i - 1] : 0;
            BOOST_CHECK_EQUAL(actual[i], expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(commitment_cache_budget_and_opening_order)
{
    using Field = ligero::vm::zkp::bn254_gmp;
    constexpr size_t k = 512, n = 4 * k;
    constexpr size_t row_words = n * 8, row_bytes = row_words * sizeof(uint32_t);
    ligero::webgpu_context gpu;
    gpu.webgpu_init(256, std::filesystem::path(PROJECT_ROOT_DIR) / "shader");
    auto [root_k, root_2k, root_n] = Field::generate_omegas(k, n);
    gpu.ntt_init(k - ligero::vm::params::sample_size, k, n,
                 Field::modulus, Field::barrett_factor, root_k, root_2k, root_n);
    gpu.sha256_init(n);
    auto context = gpu.make_device_buffer(n * sizeof(ligero::webgpu_context::sha256_context));
    auto digest = gpu.make_device_buffer(n * SHA256_DIGEST_LENGTH);
    auto input = gpu.make_device_buffer(row_bytes);
    auto bind_context = gpu.bind_sha256_context(context, digest);
    auto bind_input = gpu.bind_sha256_buffer(input);
    std::vector<size_t> indexes(ligero::vm::params::sample_size);
    for (size_t i = 0; i < indexes.size(); ++i) indexes[i] = i * 10;

    gpu.begin_commitment_cache(0);
    gpu.sha256_digest_init(bind_context);
    gpu.sha256_digest_update(bind_context, bind_input);
    BOOST_CHECK(!gpu.finish_commitment_cache());

    gpu.begin_commitment_cache(2 * row_bytes);
    gpu.sha256_digest_init(bind_context);
    for (size_t row = 0; row < 3; ++row) gpu.sha256_digest_update(bind_context, bind_input);
    BOOST_CHECK(!gpu.finish_commitment_cache());
    BOOST_CHECK_THROW(gpu.sample_cached_commitments(indexes), std::logic_error);

    // Cross the 256-row readback batching boundary and mutate the shared input
    // between rows: cached openings must retain their original values/order.
    constexpr size_t rows = 257;
    gpu.begin_commitment_cache(rows * row_bytes);
    gpu.sha256_digest_init(bind_context);
    std::vector<uint32_t> values(row_words), expected;
    expected.reserve(rows * indexes.size() * 8);
    for (size_t row = 0; row < rows; ++row) {
        for (size_t word = 0; word < values.size(); ++word) {
            values[word] = uint32_t((row + 1) * 0x1234567u) ^ uint32_t(word * 0x123457u);
        }
        gpu.write_buffer(input, values.data(), values.size());
        gpu.sha256_digest_update(bind_context, bind_input);
        for (size_t index : indexes) {
            expected.insert(expected.end(), values.begin() + index * 8,
                            values.begin() + (index + 1) * 8);
        }
    }
    std::fill(values.begin(), values.end(), 0xffffffffu);
    gpu.write_buffer(input, values.data(), values.size());
    gpu.sha256_digest_final(bind_context);
    BOOST_REQUIRE(gpu.finish_commitment_cache());
    auto short_indexes = indexes;
    short_indexes.pop_back();
    BOOST_CHECK_THROW(gpu.sample_cached_commitments(short_indexes), std::invalid_argument);
    const auto actual = gpu.sample_cached_commitments(indexes);
    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
    BOOST_CHECK_THROW(gpu.sample_cached_commitments(indexes), std::logic_error);
}
