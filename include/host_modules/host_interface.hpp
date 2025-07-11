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

#include <string>
#include <types.hpp>

namespace ligero::vm {

struct host_module {
    virtual exec_result call_host(address_t addr, std::string_view name) = 0;
    virtual void initialize() = 0;
    virtual void finalize()   = 0;
    virtual ~host_module()    = default;
};

}  // namespace ligero::vm
