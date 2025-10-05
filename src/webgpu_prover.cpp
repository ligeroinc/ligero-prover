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

#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include <transpiler.hpp>
#include <interpreter.hpp>
#include <invoke.hpp>
#include <runtime.hpp>
#include <wgpu.hpp>

#include <util/portable_sample.hpp>
#include <util/boost/portable_binary_oarchive.hpp>
#include <zkp/common.hpp>
#include <zkp/finite_field_gmp.hpp>
#include <zkp/nonbatch_context.hpp>
#include <interpreter.hpp>

#include <boost/algorithm/hex.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <wabt/error-formatter.h>
#include <wabt/wast-parser.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

using namespace ligero;
using namespace ligero::vm;
namespace io = boost::iostreams;
namespace fs = std::filesystem;

using field_t = zkp::bn254_gmp;
using executor_t = webgpu_context;
using buffer_t = typename executor_t::buffer_type;

constexpr bool enable_RAM = false;

int main(int argc, const char *argv[]) {
    const std::string ligero_version_string =
        std::format("ligero-prover v{}.{}.{}+{}.{}",
                    LIGETRON_VERSION_MAJOR,
                    LIGETRON_VERSION_MINOR,
                    LIGETRON_VERSION_PATCH,
                    LIGETRON_GIT_BRANCH,
                    LIGETRON_GIT_COMMIT_HASH);
    std::cout << ligero_version_string << std::endl;
    
    std::vector<std::vector<u8>> input_args;
    std::string shader_path;
    std::string proof_name = "proof_data.gz";

    if (argc < 2) {
        std::cerr << "Error: No JSON input provided" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    std::string_view jstr = argv[1];
    json jconfig;

    try {
        jconfig = json::parse(jstr);
    }
    catch (json::exception& e) {
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    uint64_t k = params::default_row_size;
    uint64_t l = params::default_packing_size;
    uint64_t n = params::default_encoding_size;
    
    if (jconfig.contains("packing")) {
        uint64_t packing = jconfig["packing"];
        k = packing;
        l = k - params::sample_size;
        n = 4 * k;
    }
    std::cout << "packing: " << l << ", padding: " << k << ", encoding: " << n << std::endl;

    if (jconfig.contains("shader-path")) {
        shader_path = jconfig["shader-path"].template get<std::string>();
    }

    size_t gpu_threads = k;
    if (jconfig.contains("gpu-threads")) {
        gpu_threads = jconfig["gpu-threads"].template get<size_t>();
    }
    
    {
        const std::string arg0("Ligero");
        input_args.emplace_back((u8*)arg0.c_str(), (u8*)arg0.c_str() + arg0.size() + 1);
    }
    
    if (jconfig.contains("args")) {
        for (const auto& arg : jconfig["args"]) {
            std::cout << "args: " << arg.dump() << std::endl;
            
            if (arg.contains("i64")) {
                auto i = arg["i64"].template get<int64_t>();
                input_args.emplace_back((u8*)&i, (u8*)&i + sizeof(int64_t));
            }
            else if (arg.contains("str")) {
                auto str = arg["str"].template get<std::string>();
                input_args.emplace_back((u8*)str.c_str(), (u8*)str.c_str() + str.size() + 1);
            }
            else if (arg.contains("hex")) {
                std::vector<u8> hex_vec;
                auto hex_str = arg["hex"].template get<std::string>();

                // Remove leading "0x"
                if (hex_str.starts_with("0x")) {
                    hex_str = hex_str.substr(2);
                }
                
                if (hex_str.size() % 2 == 1) {
                    hex_str.insert(hex_str.begin(), '0');
                }
                boost::algorithm::unhex(hex_str.c_str(), std::back_inserter(hex_vec));
                input_args.emplace_back(std::move(hex_vec));
            }
            else {
                std::cerr << "Error: Invalid args type: " << arg.dump() << std::endl;
                exit(EXIT_FAILURE);
            }
        }
    }

    std::unordered_set<int> indices_set;
    if (jconfig.contains("private-indices")) {
        indices_set = jconfig["private-indices"].template get<std::unordered_set<int>>();
    }

    fs::path program_name;
    if (jconfig.contains("program")) {
        program_name = jconfig["program"].template get<std::string>();
    }

    // Reading and parsing the wasm file
    // ------------------------------------------------------------
    std::unique_ptr<wabt::Module> wabt_module{ new wabt::Module{} };
    {
        std::vector<uint8_t> program_data;
        wabt::Result read_result = wabt::ReadFile(program_name.c_str(), &program_data);

        if (wabt::Failed(read_result)) {
            std::cerr << std::format("Error: Could not read from file \"{}\"",
                                     program_name.c_str())
                      << std::endl;
            exit(EXIT_FAILURE);
        }

        wabt::Features wabt_features;
        wabt::Result   parsing_result;
        wabt::Errors   parsing_errors;
        if (program_name.extension() == ".wat" || program_name.extension() == ".wast") {
            std::unique_ptr<wabt::WastLexer> lexer = wabt::WastLexer::CreateBufferLexer(
                program_name.c_str(),
                program_data.data(),
                program_data.size(),
                &parsing_errors);

            wabt::WastParseOptions parse_wast_options(wabt_features);
            parsing_result = wabt::ParseWatModule(lexer.get(),
                                                  &wabt_module,
                                                  &parsing_errors,
                                                  &parse_wast_options);
        }
        else {
            parsing_result = wabt::ReadBinaryIr(program_name.c_str(),
                                                program_data.data(),
                                                program_data.size(),
                                                wabt::ReadBinaryOptions{},
                                                &parsing_errors,
                                                wabt_module.get());
        }

        if (wabt::Failed(parsing_result)) {
            auto err_msg = wabt::FormatErrorsToString(parsing_errors,
                                                      wabt::Location::Type::Binary);
            std::cerr << std::format("wabt: {}", err_msg)
                      << std::format("Error: Failed to parse WASM module \"{}\"",
                                     program_name.c_str())
                      << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    auto [omega_k, omega_2k, omega_4k] = field_t::generate_omegas(k, n);

    executor_t executor;
    executor.webgpu_init(gpu_threads, shader_path);
    executor.ntt_init(l, k, n,
                      field_t::modulus, field_t::barrett_factor,
                      omega_k, omega_2k, omega_4k);

    std::random_device rd;
    std::mt19937 rand(rd());

    unsigned char encoding_random_seed[32];
    std::generate(std::begin(encoding_random_seed),
                  std::end(encoding_random_seed),
                  [&rand] { return rand(); });

    std::cout << "=== Start ===" << std::endl;
    
    // Stage 1
    // -------------------------------------------------------------------------------- //

    std::cout << "Start Stage 1" << std::endl;

    zkp::merkle_tree<params::hasher> tree;
    auto ctx = std::make_unique<
        zkp::nonbatch_stage1_context<field_t,
                                     executor_t,
                                     zkp::stage1_random_policy,
                                     params::hasher>>(executor);

    ctx->init_encoding_random(encoding_random_seed, params::any_iv);

    auto t1 = make_timer("stage1");
    run_program(*wabt_module, *ctx, input_args, indices_set);

    tree = ctx->flush_digests();

    params::hasher::digest stage1_root = tree.root();
    
    std::cout << "Root of Merkle Tree: ";
    zkp::show_hash(stage1_root);
    std::cout << "----------------------------------------" << std::endl;

    t1.stop();

    executor.device_synchronize();
    ctx.reset();

    // stage1.5 (for RAM only)
    // -------------------------------------------------------------------------------- //
    auto merkle_root = stage1_root;

    
    // Stage 2
    // -------------------------------------------------------------------------------- //
    std::cout << "Start Stage 2" << std::endl;

    unsigned char seed[params::hasher::digest_size];
    std::copy(merkle_root.begin(), merkle_root.end(), seed);

    buffer_t code_poly, linear_poly, quad_poly;
    
    std::array<mpz_class, params::num_linear_test> linear_sums = { 0 };
    auto t2 = make_timer("stage2");

    auto ctx2 = std::make_unique<
        zkp::nonbatch_stage2_context<field_t, executor_t, zkp::stage2_random_policy>>(executor);

    ctx2->init_encoding_random(encoding_random_seed, params::any_iv);
    ctx2->init_witness_random(seed, params::any_iv);

    run_program(*wabt_module, *ctx2, input_args, indices_set);

    linear_sums[0] = ctx2->linear_sums();
    code_poly   = ctx2->code();
    linear_poly = ctx2->linear();
    quad_poly   = ctx2->quadratic();

    t2.stop();

    mpz_vector encoded_code, encoded_linear, encoded_quad;

    auto encoded_code_limbs = executor.template copy_to_host<uint32_t>(code_poly);
    encoded_code.import_limbs(encoded_code_limbs.data(),
                              encoded_code_limbs.size(),
                              sizeof(uint32_t),
                              field_t::num_u32_limbs);

    auto encoded_linear_limbs = executor.template copy_to_host<uint32_t>(linear_poly);
    encoded_linear.import_limbs(encoded_linear_limbs.data(),
                                encoded_linear_limbs.size(),
                                sizeof(uint32_t),
                                field_t::num_u32_limbs);

    auto encoded_quad_limbs = executor.template copy_to_host<uint32_t>(quad_poly);
    encoded_quad.import_limbs(encoded_quad_limbs.data(),
                              encoded_quad_limbs.size(),
                              sizeof(uint32_t),
                              field_t::num_u32_limbs);

    auto stage2_seed = zkp::hash<params::hasher>(encoded_code_limbs,
                                                 encoded_linear_limbs,
                                                 encoded_quad_limbs);

    zkp::hash_random_engine<params::hasher> engine(stage2_seed);
    std::vector<size_t> indexes(n), sample_index;
    std::iota(indexes.begin(), indexes.end(), 0);
    portable_sample(indexes.begin(), indexes.end(),
                    std::back_inserter(sample_index),
                    params::sample_size,
                    engine);
    std::sort(sample_index.begin(), sample_index.end());

    auto decommit = tree.decommit(sample_index);

    auto bind_ntt_pc = executor.bind_ntt(code_poly);
    auto bind_ntt_pl = executor.bind_ntt(linear_poly);
    auto bind_ntt_pq = executor.bind_ntt(quad_poly);

    executor.decode_ntt_device(bind_ntt_pc);
    executor.decode_ntt_device(bind_ntt_pl);
    executor.decode_ntt_device(bind_ntt_pq);

    mpz_vector host_code, host_linear, host_quad;

    std::vector<uint32_t> code_limbs = executor.template copy_to_host<uint32_t>(code_poly);
    host_code.import_limbs(code_limbs.data(),
                           code_limbs.size(),
                           sizeof(uint32_t),
                           field_t::num_u32_limbs);

    std::vector<uint32_t> linear_limbs = executor.template copy_to_host<uint32_t>(linear_poly);
    host_linear.import_limbs(linear_limbs.data(),
                             linear_limbs.size(),
                             sizeof(uint32_t),
                             field_t::num_u32_limbs);
    host_linear.resize(l);

    std::vector<uint32_t> quad_limbs = executor.template copy_to_host<uint32_t>(quad_poly);
    host_quad.import_limbs(quad_limbs.data(),
                           quad_limbs.size(),
                           sizeof(uint32_t),
                           field_t::num_u32_limbs);
    host_quad.resize(l);

    executor.device_synchronize();
    ctx2.reset();

    std::cout << "----------------------------------------" << std::endl;

    // Stage 3
    // -------------------------------------------------------------------------------- //
    std::cout << "Start Stage 3" << std::endl;

    std::stringstream compressed_proof;
    {
        auto t3 = make_timer("stage3");

        constexpr int gzip_compression_level = 6;
        io::filtering_ostream proof_stream;
        proof_stream.push(io::gzip_compressor(io::gzip_params(gzip_compression_level)));
        proof_stream.push(compressed_proof);
        portable_binary_oarchive oa(proof_stream);
    
        oa << stage1_root
           << stage2_seed
           << encoded_code_limbs
           << encoded_linear_limbs
           << encoded_quad_limbs
           << decommit;

        auto ctx3 = std::make_unique<
            zkp::nonbatch_stage3_context<field_t,
                                         executor_t,
                                         zkp::stage3_random_policy,
                                         portable_binary_oarchive>>(executor,
                                                                    sample_index,
                                                                    oa);
        ctx3->init_encoding_random(encoding_random_seed, params::any_iv);

        run_program(*wabt_module, *ctx3, input_args, indices_set);
    }

    std::ofstream proof_file(proof_name,
                             std::ios::out | std::ios::binary | std::ios::trunc);

    if (!proof_file) {
        std::cerr << std::format("Error: Could not write to file \"{}\"", proof_name)
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    proof_file << compressed_proof.rdbuf();
    proof_file.close();

    // ================================================================================

    std::cout << std::boolalpha;

    bool valid_code = std::all_of(host_code.begin() + k, host_code.end(),
                                  [](const auto& x) { return x == 0; });
    bool valid_linear = zkp::validate_sum<field_t>(host_linear, linear_sums[0]);
    bool valid_quad   = zkp::validate(host_quad);

    bool prove_result = valid_code && valid_linear && valid_quad;

    std::cout << std::endl;
    std::cout << "Prover root: ";
    zkp::show_hash(stage1_root);
    std::cout << "Validation of encoding:              ";
    std::cout << valid_code << " " << std::endl;
    std::cout << "Validation of linear constraints:    ";
    std::cout << valid_linear << " " << std::endl;
    std::cout << "Validation of quadratic constraints: ";
    std::cout << valid_quad << " " << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    std::cout << "Final prove result:                  " << prove_result << std::endl;

    show_timer();

#if defined(__EMSCRIPTEN__)
    // Since wasm remains loaded in memory after the "main" invocation,
    // timers are not cleaned up before the next invocation,
    // therefore we need to do it manually.
    clear_timers();
#endif
    return !prove_result;
}
