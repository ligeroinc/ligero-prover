#include <ligetron/webgpu/powmod_context.hpp>

#define BOOST_TEST_MODULE "WebGPU.powmod"

#include <vector>
#include <boost/test/included/unit_test.hpp>
#include <zkp/finite_field_gmp.hpp>

using namespace ligero;
using namespace ligero::vm::zkp;
namespace fs = std::filesystem;

using bignum_type = webgpu::device_uint256_t;
static const fs::path root_path = fs::path(PROJECT_ROOT_DIR);
constexpr size_t test_size = 8192;
constexpr size_t test_limb_size = test_size * bignum_type::num_limbs;
constexpr size_t exp_buffer_size = test_size * sizeof(uint32_t);
constexpr size_t test_buffer_size = test_size * bignum_type::num_bytes;
constexpr size_t test_workgroups = webgpu::calc_blocks(test_size, webgpu::workgroup_size);

struct powmod_fixture {
    powmod_fixture() : powmod_(&device_, 32) {
        device_.device_init();
        shader_ = webgpu::load_shader(device_.device(),
                                      root_path / "shader" / "bignum.wgsl");
        powmod_.init_layout();
        powmod_.init_pipeline(shader_);
        powmod_.init_precompute();

        exp   = device_.make_device_buffer(exp_buffer_size);
        coeff = device_.make_device_buffer(test_buffer_size);
        out   = device_.make_device_buffer(test_buffer_size);
        bind  = powmod_.bind_buffer(exp, coeff, out);
    }

    ~powmod_fixture() {
        
    }

    webgpu::device_context device_;
    webgpu::powmod_context<bignum_type> powmod_;
    WGPUShaderModule shader_;

    webgpu::buffer_view exp;
    webgpu::buffer_view coeff;
    webgpu::buffer_view out;
    webgpu::buffer_binding bind;
};

BOOST_FIXTURE_TEST_CASE(test_zero, powmod_fixture)
{
    powmod_.set_base(1, bn254_gmp::modulus);
    
    powmod_.powmod_kernel(bind, test_workgroups);
    device_.device_synchronize();

    std::vector<uint32_t> ref_limbs(test_limb_size, 0u);
    auto limbs = device_.copy_to_host<uint32_t>(out);
    
    BOOST_CHECK_EQUAL_COLLECTIONS(limbs.begin(), limbs.end(), ref_limbs.begin(), ref_limbs.end());
}


BOOST_FIXTURE_TEST_CASE(test_one, powmod_fixture)
{
    powmod_.set_base(1, bn254_gmp::modulus);

    bignum_type one(1);
    std::vector<bignum_type> host_buf(test_size, one);
    device_.write_buffer(coeff, host_buf.data(), host_buf.size());

    std::vector<uint32_t> host_exp(test_size, 1u);
    device_.write_buffer(exp, host_exp.data(), host_exp.size());
    
    powmod_.powmod_kernel(bind, test_workgroups);
    device_.device_synchronize();

    std::vector<uint32_t> ref_limbs(test_limb_size, 0u);
    for (size_t i = 0; i < test_size; i++) {
        ref_limbs[i * bignum_type::num_limbs] = 1u;
    }
    
    auto limbs = device_.copy_to_host<uint32_t>(out);
    
    BOOST_CHECK_EQUAL_COLLECTIONS(limbs.begin(), limbs.end(), ref_limbs.begin(), ref_limbs.end());
}


BOOST_FIXTURE_TEST_CASE(test_generator, powmod_fixture)
{
    mpz_class base = 7;
    powmod_.set_base(base, bn254_gmp::modulus);

    bignum_type one(1);
    std::vector<bignum_type> host_buf(test_size, one);
    device_.write_buffer(coeff, host_buf.data(), host_buf.size());

    std::vector<uint32_t> host_exp(test_size);    
    std::iota(host_exp.begin(), host_exp.end(), 0);
    device_.write_buffer(exp, host_exp.data(), host_exp.size());
    
    powmod_.powmod_kernel(bind, test_workgroups);
    device_.device_synchronize();

    std::vector<uint32_t> ref_limbs(test_limb_size);
    mpz_class pow;
    for (size_t i = 0; i < test_size; i++) {
        mpz_powm_ui(pow.get_mpz_t(),
                    base.get_mpz_t(),
                    i,
                    bn254_gmp::modulus.get_mpz_t());
        bignum_type tmp(pow);
        for (size_t k = 0; k < bignum_type::num_limbs; k++) {
            ref_limbs[i * bignum_type::num_limbs + k] = tmp[k];            
        }
    }
    
    auto limbs = device_.copy_to_host<uint32_t>(out);
    
    BOOST_CHECK_EQUAL_COLLECTIONS(limbs.begin(), limbs.end(), ref_limbs.begin(), ref_limbs.end());
}


BOOST_FIXTURE_TEST_CASE(test_minus, powmod_fixture)
{
    mpz_class base = bn254_gmp::modulus - 1;
    powmod_.set_base(base, bn254_gmp::modulus);

    bignum_type one(base);
    std::vector<bignum_type> host_buf(test_size, one);
    device_.write_buffer(coeff, host_buf.data(), host_buf.size());

    std::vector<uint32_t> host_exp(test_size);    
    std::iota(host_exp.begin(), host_exp.end(), 1u << 16);
    device_.write_buffer(exp, host_exp.data(), host_exp.size());
    
    powmod_.powmod_kernel(bind, test_workgroups);
    device_.device_synchronize();

    std::vector<uint32_t> ref_limbs(test_limb_size);
    mpz_class pow;
    for (size_t i = 0; i < test_size; i++) {
        mpz_powm_ui(pow.get_mpz_t(),
                    base.get_mpz_t(),
                    (1u << 16) + i + 1,
                    bn254_gmp::modulus.get_mpz_t());
        bignum_type tmp(pow);
        for (size_t k = 0; k < bignum_type::num_limbs; k++) {
            ref_limbs[i * bignum_type::num_limbs + k] = tmp[k];            
        }
    }
    
    auto limbs = device_.copy_to_host<uint32_t>(out);
    
    BOOST_CHECK_EQUAL_COLLECTIONS(limbs.begin(), limbs.end(), ref_limbs.begin(), ref_limbs.end());
}


BOOST_FIXTURE_TEST_CASE(test_powmod_add, powmod_fixture)
{
    mpz_class base = 7;
    powmod_.set_base(base, bn254_gmp::modulus);

    bignum_type one(1);
    std::vector<bignum_type> host_buf(test_size, one);
    device_.write_buffer(coeff, host_buf.data(), host_buf.size());

    std::vector<uint32_t> host_exp(test_size);    
    std::iota(host_exp.begin(), host_exp.end(), 0);
    device_.write_buffer(exp, host_exp.data(), host_exp.size());
    
    powmod_.powmod_kernel(bind, test_workgroups);

    for (size_t i = 0; i < 9; i++) {
        powmod_.powmod_add_kernel(bind, test_workgroups);
    }

    device_.device_synchronize();

    std::vector<uint32_t> ref_limbs(test_limb_size);
    mpz_class pow;
    for (size_t i = 0; i < test_size; i++) {
        mpz_powm_ui(pow.get_mpz_t(),
                    base.get_mpz_t(),
                    i,
                    bn254_gmp::modulus.get_mpz_t());
        pow = pow * 10 % bn254_gmp::modulus;
        bignum_type tmp(pow);
        for (size_t k = 0; k < bignum_type::num_limbs; k++) {
            ref_limbs[i * bignum_type::num_limbs + k] = tmp[k];            
        }
    }
    
    auto limbs = device_.copy_to_host<uint32_t>(out);
    
    BOOST_CHECK_EQUAL_COLLECTIONS(limbs.begin(), limbs.end(), ref_limbs.begin(), ref_limbs.end());
}
