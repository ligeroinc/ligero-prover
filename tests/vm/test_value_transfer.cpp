// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// CPU-only checks of the real interpreter/context value-transfer paths.
#include <runtime.hpp>
#include <wgpu.hpp>
#include <zkp/finite_field_gmp.hpp>
#include <zkp/nonbatch_context.hpp>
#include <interpreter.hpp>

#include <bit>
#include <iostream>
#include <stdexcept>

namespace {
using namespace ligero;
using namespace ligero::vm;
using namespace ligero::vm::zkp;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct CPUExecutor {
    size_t message_size() const { return 64; }
    size_t padding_size() const { return 64; }
};

struct Context : nonbatch_context_base<bn254_gmp, CPUExecutor, stage1_random_policy> {
    using Base = nonbatch_context_base<bn254_gmp, CPUExecutor, stage1_random_policy>;
    using Base::Base;
    void linear_callback(witness_row_type) override {}
    void quadratic_callback(witness_row_type, witness_row_type, witness_row_type) override {}
    void mask_callback(mpz_vector&, mpz_vector&, mpz_vector&) override {}
    size_t stack_size() const { return stack_.size(); }
};

// Independent reference: the pre-optimization local.get/local.tee code.
void reference_get(Context& ctx, size_t index) {
    ctx.stack_push(std::visit(prelude::overloaded{
        [](std::unique_ptr<wasm_frame>&) -> stack_value {
            throw wasm_trap("local_get: Unexpected frame pointer");
        },
        [](auto& value) { return stack_value{value}; }
    }, ctx.current_frame()->locals[index].data()));
}

void reference_tee(Context& ctx, size_t index) {
    ctx.current_frame()->locals[index] = std::visit(prelude::overloaded{
        [](std::unique_ptr<wasm_frame>&) -> stack_value {
            throw wasm_trap("local_tee: Unexpected frame pointer");
        },
        [](auto& value) { return stack_value{value}; }
    }, ctx.stack_peek().data());
}

void require_numeric(const stack_value& actual, const native_numeric& expected) {
    require(actual.is_val() && actual.as_numeric().type() == expected.type(), "numeric type changed");
    switch (expected.type()) {
    case native_numeric::i32:
        require(actual.as_u32() == expected.as_u32(), "i32 bits changed"); break;
    case native_numeric::i64:
        require(actual.as_u64() == expected.as_u64(), "i64 bits changed"); break;
    case native_numeric::f32:
        require(std::bit_cast<u32>(actual.as_f32()) == std::bit_cast<u32>(expected.as_f32()),
                "f32 bits changed"); break;
    case native_numeric::f64:
        require(std::bit_cast<u64>(actual.as_f64()) == std::bit_cast<u64>(expected.as_f64()),
                "f64 bits changed"); break;
    }
}

void check_numeric() {
    CPUExecutor executor;
    Context ctx(executor);
    opcode_interpreter interp(ctx);
    wasm_frame frame;
    frame.locals.resize(3);
    ctx.set_current_frame(&frame);
    const std::vector<native_numeric> values{
        u32(0), u32(0x80000000), u32(0xffffffff),
        u64(0), u64(0xfedcba9876543210), u64(0xffffffffffffffff),
        std::bit_cast<float>(u32(0)), std::bit_cast<float>(u32(0x80000000)),
        std::bit_cast<float>(u32(0x7fc12345)), std::bit_cast<float>(u32(0x7f800000)),
        std::bit_cast<float>(u32(1)), std::bit_cast<double>(u64(0)),
        std::bit_cast<double>(u64(0x8000000000000000)),
        std::bit_cast<double>(u64(0x7ff8123456789abc)),
        std::bit_cast<double>(u64(0xfff0000000000000)), std::bit_cast<double>(u64(1))};
    for (const auto& value : values) {
        frame.locals[0] = stack_value(value);
        interp.exec_local_get(opcode(opcode::local_get, 0));
        require_numeric(ctx.stack_peek(), value);
        interp.exec_local_tee(opcode(opcode::local_tee, 1));
        require_numeric(frame.locals[1], value);
        require_numeric(ctx.stack_peek(), value);
        interp.exec_local_set(opcode(opcode::local_set, 2));
        require_numeric(frame.locals[2], value);
        require(ctx.stack_size() == 0, "local operations changed stack height");

        // Repeated aliasing pushes exercise vector growth without retaining a
        // reference into the old stack allocation.
        ctx.stack_push(value);
        for (unsigned i = 0; i < 130; ++i) ctx.stack_push(ctx.stack_peek().as_numeric());
        while (ctx.stack_size()) require_numeric(ctx.stack_pop(), value);
    }
    ctx.stack_push(u32(0xffffffff));
    require_numeric(ctx.stack_pop(), native_numeric(u32(0xffffffff)));
    ctx.stack_push(u64(0xfedcba9876543210));
    require_numeric(ctx.stack_pop(), native_numeric(u64(0xfedcba9876543210)));
    ctx.stack_push(-1);
    require_numeric(ctx.stack_pop(), native_numeric(-1));
    ctx.stack_push(-0.0f);
    require_numeric(ctx.stack_pop(), native_numeric(-0.0f));
    ctx.stack_push(-0.0);
    require_numeric(ctx.stack_pop(), native_numeric(-0.0));

    // These invalid value kinds must still take the existing trap path without
    // mutating the source or destination, rather than being treated as numeric.
    frame.locals[0] = stack_value(std::make_unique<wasm_frame>());
    bool trapped = false;
    try { interp.exec_local_get(opcode(opcode::local_get, 0)); }
    catch (const wasm_trap&) { trapped = true; }
    require(trapped && ctx.stack_size() == 0 && frame.locals[0].is_frame(),
            "frame local.get trap changed");
    frame.locals[1] = stack_value(u32(23));
    ctx.stack_push(std::make_unique<wasm_frame>());
    trapped = false;
    try { interp.exec_local_tee(opcode(opcode::local_tee, 1)); }
    catch (const wasm_trap&) { trapped = true; }
    require(trapped && ctx.stack_peek().is_frame() && frame.locals[1].as_u32() == 23,
            "frame local.tee trap changed");
    ctx.stack_pop();
}

managed_witness counted_witness(std::vector<int>& released, int id) {
    return managed_witness(std::shared_ptr<lazy_witness>(new lazy_witness,
        [&released, id](lazy_witness* value) { released.push_back(id); delete value; }));
}

std::vector<int> ownership_sequence(bool reference) {
    std::vector<int> released;
    CPUExecutor executor;
    Context ctx(executor);
    opcode_interpreter interp(ctx);
    const auto get = [&](size_t index) {
        if (reference) reference_get(ctx, index);
        else interp.exec_local_get(opcode(opcode::local_get, index));
    };
    const auto tee = [&](size_t index) {
        if (reference) reference_tee(ctx, index);
        else interp.exec_local_tee(opcode(opcode::local_tee, index));
    };
    auto frame = ctx.make_frame();
    frame->locals.resize(3);
    auto* locals = frame.get();
    ctx.set_current_frame(frame.get());
    ctx.stack_push(std::move(frame));

    locals->locals[0] = stack_value(counted_witness(released, 1));
    auto* identity = locals->locals[0].as_witness().get();
    get(0);
    require(ctx.stack_peek().as_witness().get() == identity, "local.get cloned witness");
    tee(1);
    require(locals->locals[1].as_witness().get() == identity, "local.tee cloned witness");
    require(locals->locals[1].as_witness().data().use_count() == 3, "witness aliases changed");
    ctx.stack_pop();
    locals->locals[0] = stack_value(0);
    require(released.empty(), "witness released before last alias");
    ctx.stack_push(u64(0x8000000000000001));
    tee(1); // Numeric replacement must release the former local owner now.
    require(released == std::vector<int>{1}, "numeric tee changed witness release timing");
    ctx.stack_pop();

    decomposed_bits bits;
    for (int id : {2, 3, 4}) bits.push_back(counted_witness(released, id));
    locals->locals[0] = stack_value(bits);
    bits.data().clear();
    get(0);
    tee(1);
    for (size_t i = 0; i < 3; ++i) {
        require(ctx.stack_peek().as_decomposed_bits()[i].get() ==
                locals->locals[0].as_decomposed_bits()[i].get(), "bit aliases changed");
    }
    ctx.stack_pop();
    locals->locals[0] = stack_value(0);
    require(released == std::vector<int>{1}, "bits released before last alias");
    ctx.stack_push(u32(7));
    tee(1);
    ctx.stack_pop();
    require(released == std::vector<int>({1, 4, 3, 2}), "bit reverse release changed");

    locals->locals[0] = stack_value(reference_t{0xfedcba98});
    get(0); tee(1);
    require(ctx.stack_pop().as_ref() == reference_t{0xfedcba98}, "reference get changed");
    require(locals->locals[1].as_ref() == reference_t{0xfedcba98}, "reference tee changed");
    locals->locals[0] = stack_value(reference_t{});
    get(0); tee(1);
    require(!ctx.stack_pop().as_ref() && !locals->locals[1].as_ref(), "null reference changed");

    // Nested frames must still destroy locals in reverse order and restore the
    // previous current_frame; their stack storage may have moved meanwhile.
    locals->locals[0] = stack_value(counted_witness(released, 5));
    locals->locals[1] = stack_value(counted_witness(released, 6));
    auto nested = ctx.make_frame();
    nested->locals.emplace_back(counted_witness(released, 7));
    nested->locals.emplace_back(counted_witness(released, 8));
    ctx.set_current_frame(nested.get());
    ctx.stack_push(std::move(nested));
    ctx.drop_n_below(1);
    require(ctx.current_frame() == locals, "nested frame was not restored");
    ctx.drop_n_below(1);
    require(ctx.stack_size() == 0, "frame cleanup changed stack height");
    require(released == std::vector<int>({1, 4, 3, 2, 8, 7, 6, 5}), "frame release order changed");
    return released;
}

struct Host : host_module {
    static constexpr const char* module_name = "test.host";
    int id;
    std::vector<std::string>* calls;
    Host(int value, std::vector<std::string>* out) : id(value), calls(out) {}
    void initialize() override {}
    void finalize() override {}
    exec_result call_host(address_t address, std::string_view name) override {
        calls->push_back(std::to_string(id) + ":" + std::to_string(address) + ":" + std::string(name));
        return exec_ok();
    }
};
struct OtherHost : Host {
    static constexpr const char* module_name = "other.host";
    using Host::Host;
};

function_instance::host_code& host_code(store_t& store) {
    return std::get<function_instance::host_code>(store.functions[0].code);
}

void initialize_store(store_t& store, const char* module) {
    store.functions.emplace_back(function_kind{});
    store.functions[0].code = function_instance::host_code{0, module, "first"};
}

void check_host_resolution() {
    CPUExecutor executor;
    Context ctx(executor), other(executor);
    std::vector<std::string> calls;
    store_t store, replacement;
    initialize_store(store, Host::module_name);
    initialize_store(replacement, OtherHost::module_name);
    ctx.store(&store);
    ctx.add_host_module<Host>(1, &calls);
    ctx.add_host_module<OtherHost>(2, &calls);
    ctx.call_host(0, host_code(store));
    ctx.call_host(0, host_code(store));
    host_code(store).name = "renamed";
    ctx.call_host(0, host_code(store));
    host_code(store).module = OtherHost::module_name;
    ctx.call_host(0, host_code(store)); // Same host_code address, new module.
    store.functions[0].code = function_instance::host_code{0, Host::module_name, "replaced"};
    ctx.call_host(0, host_code(store));
    store.functions.reserve(store.functions.capacity() + 128);
    ctx.call_host(0, host_code(store)); // Function vector relocated.
    ctx.add_host_module<Host>(3, &calls);
    ctx.call_host(0, host_code(store)); // Registered module replaced.
    other.store(&store);
    other.add_host_module<Host>(4, &calls);
    other.call_host(0, host_code(store)); // Same store, different context.
    ctx.store(&replacement);
    ctx.call_host(0, host_code(replacement));
    ctx.store(&store);
    ctx.call_host(0, host_code(store));
    host_code(store).module = "not.registered";
    const auto missing = ctx.call_host(0, host_code(store));
    require(missing.is_exit() && missing.exit_code() == -1, "missing module no longer exits");
    host_code(store).module = OtherHost::module_name;
    ctx.call_host(0, host_code(store));
    require(calls == std::vector<std::string>{
        "1:0:first", "1:0:first", "1:0:renamed", "2:0:renamed",
        "1:0:replaced", "1:0:replaced", "3:0:replaced", "4:0:replaced",
        "2:0:first", "3:0:replaced", "2:0:replaced"}, "cached host dispatch changed");
}
} // namespace

int main() {
    try {
        check_numeric();
        require(ownership_sequence(false) == ownership_sequence(true), "ownership reference mismatch");
        check_host_resolution();
        std::cout << "numeric transfers, ownership/release ordering, host dispatch: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
