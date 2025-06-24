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

#pragma once

#include <algorithm>
#include <random>
#include <sys/uio.h>
#include <host_modules/host_interface.hpp>

using namespace std::string_literals;
namespace fs = std::filesystem;

extern char **environ;

namespace ligero::vm {

struct wasi_iovec {
    u32 ptr;
    u32 len;
};

template <typename Context>
struct wasi_preview1_module : public host_module {
    constexpr static auto module_name = "wasi_snapshot_preview1";

    using Self = wasi_preview1_module<Context>;
    typedef exec_result (Self::*host_function_type)();

    wasi_preview1_module(Context *ctx,
                         const std::vector<std::vector<u8>>& args,
                         const std::unordered_set<int>& private_indices)
        : ctx_(ctx),
          rand_(1145141919),
          args_(args),
          private_indices_(private_indices)
        { }

    exec_result args_sizes_get() {
        u32 size_ptr  = ctx_->stack_pop().as_u32();
        u32 count_ptr = ctx_->stack_pop().as_u32();

        u32 argc = args_.size();
        ctx_->memory_store(count_ptr, argc);

        u32 buffer_size = 0;
        for (const auto& arg : args_) {
            buffer_size += arg.size();
        }
        ctx_->memory_store(size_ptr, buffer_size);

        // std::cout << "set argc: mem[" << count_ptr << "] = " << argc << std::endl
        //           << "set argv: mem[" << size_ptr << "] = " << buffer_size << std::endl;

        ctx_->stack_push(0);
        return exec_ok();
    }

    exec_result args_get() {
        u32 argv_buffer = ctx_->stack_pop().as_u32();
        u32 argv        = ctx_->stack_pop().as_u32();

        address_t addr = ctx_->module()->memaddrs[0];
        memory_instance& mem = ctx_->store()->memorys[addr];

        for (int i = 0; i < args_.size(); i++) {
            ctx_->memory_store(argv, argv_buffer);
            argv += sizeof(u32);

            std::memcpy(ctx_->memory() + argv_buffer, args_[i].data(), args_[i].size());

            // std::cout << "argv[" << i << "] = " << mem8 + argv_buffer << std::endl;

            if (private_indices_.contains(i)) {
                mem.mark_secret_closed(argv_buffer, argv_buffer + args_[i].size());
            }
            else {
                // TODO: assert public input
            }

            argv_buffer += args_[i].size();
        }

        ctx_->stack_push(0);
        return exec_ok();
    }

    exec_result environ_sizes_get() {
        u32 size_ptr  = ctx_->stack_pop().as_u32();
        u32 count_ptr = ctx_->stack_pop().as_u32();

        u32 environ_count = 0;
        u32 environ_size  = 0;

        for (char **env = environ; *env != nullptr; ++env) {
            ++environ_count;
            environ_size += std::strlen(*env) + 1;  // include null terminator

            std::cout << "environ[" << environ_count << "]: " << *env << std::endl;
        }

        ctx_->memory_store(count_ptr, environ_count);
        ctx_->memory_store(size_ptr, environ_size);

        ctx_->stack_push(0);
        return exec_ok();
    }

    exec_result environ_get() {
        u32 environ_buffer = ctx_->stack_pop().as_u32();
        u32 environ_ptr    = ctx_->stack_pop().as_u32();

        for (char **env = environ; *env != nullptr; ++env) {
            ctx_->memory_store(environ_ptr, environ_buffer);
            environ_ptr += sizeof(u32);

            std::strcpy(reinterpret_cast<char*>(ctx_->memory() + environ_buffer), *env);
            environ_buffer += std::strlen(*env) + 1;  // include null terminator
        }

        ctx_->stack_push(0);
        return exec_ok();
    }

    exec_result fd_read() {
        u32 nread_ptr  = ctx_->stack_pop().as_u32();
        u32 iovec_len  = ctx_->stack_pop().as_u32();
        u32 iovec_ptr  = ctx_->stack_pop().as_u32();
        u32 fd         = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory();
        u32* nread = reinterpret_cast<u32*>(mem + nread_ptr);

        struct iovec iovec[iovec_len];
        wasi_iovec *iov = reinterpret_cast<wasi_iovec*>(mem + iovec_ptr);

        for (size_t i = 0; i < iovec_len; i++) {
            iovec[i].iov_base = static_cast<void*>(mem + iov[i].ptr);
            iovec[i].iov_len = iov[i].len;
        }

        s32 read_byte = readv(fd, iovec, iovec_len);
        assert(read_byte != 0);

        ctx_->stack_push(read_byte == -1 ? errno : 0);

        *nread = static_cast<u32>(read_byte);
        return exec_ok();
    }

    exec_result fd_write() {
        u32 nwrite_ptr = ctx_->stack_pop().as_u32();
        u32 iovec_len  = ctx_->stack_pop().as_u32();
        u32 iovec_ptr  = ctx_->stack_pop().as_u32();
        u32 fd         = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory();
        u32* nwrite = reinterpret_cast<u32*>(mem + nwrite_ptr);

        struct iovec iovec[iovec_len];
        wasi_iovec *iov = reinterpret_cast<wasi_iovec*>(mem + iovec_ptr);

        for (size_t i = 0; i < iovec_len; i++) {
            iovec[i].iov_base = static_cast<void*>(mem + iov[i].ptr);
            iovec[i].iov_len = iov[i].len;
        }

        s32 written = writev(fd, iovec, iovec_len);
        assert(written != 0);

        ctx_->stack_push(written == -1 ? errno : 0);

        *nwrite = static_cast<u32>(written);
        return exec_ok();
    }

    exec_result proc_exit() {
        auto code = ctx_->stack_pop();
        u32 err_code = ctx_->make_numeric(std::move(code)).as_u32();

        return exec_exit{ .exit_code = static_cast<int>(err_code) };
    }

    exec_result random_get() {
        u32 buf_len = ctx_->stack_pop().as_u32();
        u32 buf_ptr = ctx_->stack_pop().as_u32();

        u8* buf = ctx_->memory() + buf_ptr;

        std::uniform_int_distribution<> dist(0, 255);
        auto gen = [&] { return static_cast<u8>(dist(rand_)); };
        std::generate(buf, buf + buf_len, gen);

        ctx_->stack_push(0);
        return exec_ok();
    }

    void initialize() override {
        call_lookup_table_ = {
            { "args_get",              &Self::args_get               },
            { "args_sizes_get",        &Self::args_sizes_get         },
            // { "clock_time_get",        &Self::undefined              },
            { "environ_get",           &Self::environ_get            },
            { "environ_sizes_get",     &Self::environ_sizes_get      },
            // { "fd_close",              &Self::undefined              },
            // { "fd_fdstat_get",         &Self::undefined              },
            // { "fd_filestat_get",       &Self::undefined              },
            // { "fd_prestat_dir_name",   &Self::undefined              },
            // { "fd_prestat_get",        &Self::undefined              },
            { "fd_read",               &Self::fd_read                },
            // { "fd_readdir",            &Self::undefined              },
            // { "fd_seek",               &Self::undefined              },
            { "fd_write",              &Self::fd_write               },
            // { "path_filestat_get",     &Self::undefined              },
            // { "path_open",             &Self::undefined              },
            { "proc_exit",             &Self::proc_exit              },
            { "random_get",            &Self::random_get             },
        };
    }

    void finalize() override {

    }

    exec_result call_host(address_t addr, std::string_view func) override {
        return (this->*call_lookup_table_[func])();
    }

protected:
    Context *ctx_ = nullptr;
    std::mt19937 rand_;
    std::vector<std::vector<u8>> args_;
    std::unordered_set<int> private_indices_;
    std::unordered_map<std::string_view, host_function_type> call_lookup_table_;
};



}  // namespace ligero::vm
