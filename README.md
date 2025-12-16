<p align="center">
  <a href="https://ligero-inc.com/" target="_blank">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://framerusercontent.com/images/kw9EvSUc7tJM1JZrPk1bZHE2QOQ.png?scale-down-to=512">
      <img src="https://framerusercontent.com/images/kw9EvSUc7tJM1JZrPk1bZHE2QOQ.png?scale-down-to=512" alt="Ligero Company Logo" width="291" height="84">
    </picture>
  </a>
</p>

[![License](https://img.shields.io/badge/license-Apache_2.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build](https://img.shields.io/badge/build-success-green)](https://img.shields.io/badge/build-success-green)
[![X](https://img.shields.io/badge/@ligero__inc-000000?logo=x&logoColor=white)](https://x.com/ligero_inc)
[![Telegram](https://img.shields.io/badge/Join_Telegram-2CA5E0?logo=telegram&logoColor=white)](https://t.me/+4wP_vBTuoKwyYzgx)

# Downloading and Building Ligetron

This README will guide you through the process of downloading and building Ligetron.

<details>
<summary><b><u>macOS Setup Instructions</u></b></summary>

These are the steps to clone, build, and run the Ligetron SDK natively or for the web on macOS.

This guide assumes you have `git` installed on your system.

---

## 📦 Prerequisites

Install the [Homebrew](https://brew.sh/) package manager:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install the following via Homebrew:

```bash
brew install cmake gmp mpfr libomp llvm boost
```
</details>

<details>
<summary><b><u>Ubuntu Setup Instructions</u></b></summary>

## Prerequisites
Before proceeding, make sure you have the following prerequisites:

* Ubuntu 22.04 or newer is installed on your system. (Ubuntu 24.04 preferred)
* Update your Ubuntu system by running the following command in your terminal:

``` bash
sudo apt-get update && sudo apt-get upgrade -y
```

* Install necessary dependencies by running the following command in your terminal:

```bash
sudo apt-get install g++ libgmp-dev libtbb-dev cmake libssl-dev libboost-all-dev -y
```

* `git` should be installed on your system. If it is not installed, you can download and install it by running the following command in your terminal:

``` bash
sudo apt-get install git -y
```
* X11 may need to be installed:

``` bash
sudo apt install libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev
sudo apt install libx11-xcb-dev
```

* g++ 13 also may need installing:

``` bash
# Add the Ubuntu Toolchain PPA
sudo add-apt-repository ppa:ubuntu-toolchain-r/test

# Update package lists
sudo apt update

# Install GCC 13
sudo apt install g++-13

# Configure Alternatives
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 20
sudo update-alternatives --set g++ "/usr/bin/g++-13"
```

* Install Vulkan

``` bash
sudo apt install libvulkan1 vulkan-tools
```

* cmake may need to be upgraded:

``` bash
# Remove old CMake version if installed
sudo apt remove --purge cmake
sudo apt autoremove

# Install required packages
sudo apt install -y software-properties-common lsb-release wget gpg

# Add Kitware's repository and its signing key
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null

# Add the repository to sources list
echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null

# Update package lists
sudo apt update

# Install the latest CMake
sudo apt install cmake

# Verify the installation
cmake --version
```

* install NVIDIA drivers and suport:
``` bash
sudo apt purge nvidia*
sudo apt install nvidia-driver-535 nvidia-dkms-535 nvidia-utils-535
sudo reboot
```

* finally, openGL may need installing:

``` bash
sudo apt install mesa-common-dev libgl1-mesa-dev
```
</details>

---
## Build Webgpu (Dawn)

[Instructions](https://dawn.googlesource.com/dawn/+/refs/heads/main/docs/quickstart-cmake.md)

From a convenient location:
```bash
git clone https://dawn.googlesource.com/dawn
cd dawn/
git checkout cec4482eccee45696a7c0019e750c77f101ced04
mkdir release && cd release
cmake -DDAWN_FETCH_DEPENDENCIES=ON -DDAWN_BUILD_MONOLITHIC_LIBRARY=STATIC -DDAWN_ENABLE_INSTALL=ON -DCMAKE_BUILD_TYPE=Release ..
make -j
make install
```

---
## Building Dependencies

Ligetron also depends on several external libraries:

* [WebAssembly Binary Toolkit](https://github.com/WebAssembly/wabt.git)
* [nlohmann json](https://github.com/nlohmann/json.git)

From a convenient location:
``` bash
git clone https://github.com/WebAssembly/wabt.git
cd wabt
git submodule update --init
mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=g++-13 .. # For Ubuntu
cmake -DCMAKE_CXX_COMPILER=clang++ .. # For MacOS
make -j
sudo make install
```

---
## Install emscripten

From a convenient location:
```bash
# Get the emsdk repo
git clone https://github.com/emscripten-core/emsdk.git
# Enter that directory
cd emsdk
# Fetch the latest version of the emsdk (not needed the first time you clone)
git pull
# Download and install the latest SDK tools.
./emsdk install latest
# Make the "latest" SDK "active" for the current user. (writes .emscripten file)
./emsdk activate latest
# Activate PATH and other environment variables in the current terminal
source ./emsdk_env.sh
```

---
## Downloading and Building Ligetron

``` bash
git clone https://github.com/ligeroinc/ligetron.git
cd ligetron
```

---

### Build the native version of the Prover/Verifier

From the project root directory:
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

---
### Build the web version of the Prover/Verifier

First, make sure Emscripten is installed and activated on your system. See [Install Emscripten](#install-emscripten) for more details.

Before we continue, it's important to understand how the web build works:
- All dependencies must be built as WASM and installed to `<path-to-wasm-libs>`. To make life easier, we provide a repo that contains precompiled dependencies: [wasm-libs](https://github.com/ligeroinc/wasm-libs).
- To avoid uploading the shader and application each time opening the page, we use Emscripten's preload feature. All contents in the `<build-directory>/pack` folder will be automatically bundled at compile time. (Remember to clear the cache after changing the contents since it won't trigger a recompile.)
- The target prover/verifier WASM will be embedded in an HTML shell (the default one is `emscripten_templates/edit_distance.html`). Depending on your needs, you can customize the shell to take a different number of inputs.

From the project root directory:
``` bash
mkdir -p build-web && cd build-web
# build system will automatically create "pack" bundle subdirectory in the build directory,
# and copy directory with webgpu shaders there
#
# (Optional) If we need to copy the application wasm into the bundle:
mkdir pack             # Manually pre-create the preload bundle directory
cp app.wasm pack/      # copy the application into the bundle directory
#
emcmake cmake -DCMAKE_BUILD_TYPE=Web -DCMAKE_PREFIX_PATH=<path-to-wasm-libs> ..
emmake make
```

**IMPORTANT**

Although it's tempting to double-click and open the `webgpu_prover.html`, it won't work since the strict browser CORS rules prohibit loading other files from localhost. Use `emrun` or hosting a HTTP server instead:

```bash
emrun --browser chrome webgpu_prover.html
```

---
### Build the C++ version of the SDK

[Step by step instructions here](https://github.com/ligeroinc/ligetron/blob/main/sdk/cpp/README.md)

From the project root
```bash
cd sdk/cpp
mkdir build && cd build
emcmake cmake ..
make -j
```

---
### Build the Rust version of the SDK

From the project root
```bash
cd sdk/rust
cargo build --target wasm32-wasip1 --release
```

## Running the Prover/Verifier

To run the the prover follow these steps:

### prover
* Navigate to the build directory and run the following command to run the prover:

``` bash
./webgpu_prover <string of JSON object>
```
where the single argument is a string produced by `JSON.stringify()`. Here is the fields of the JSON:

|       Field       | Type     | Required |   Default  |          Description         |
| ----------------- | -------- | -------- | ---------- | ---------------------------- |
| `program`         | string   | &check;  |            | Path to the application wasm |
| `gpu-threads`     | int      |          | packing    | Number of GPU threads to use (can be more than physical cores) |
| `shader-path`     | string   |          | "./shader" | Path to the folder contains GPU shaders |
| `packing`         | int      |          | 8192       | FFT message packing size (doubled for codeword) |
| `private-indices` | [int]    |          | []         | Index of private arguments. Start from 1 |
| `args`            | [object] |          | []         | Program arguments. Objects are in the form of { <type> : <val> } where `type` is `str`/`i64`/`hex` |

**Note**: Packing size influences the proof length. This parameter needs to be optimally chosen to minimize proof length.

### verifier
* Navigate to the build directory and run the following command to run the verifier:

``` bash
./webgpu_verifier <equivalent JSON argument as for demo, but with obscured private indices>
```
## Examples

**Note:** When in doubt, it's always a good idea to recompile the example again from source in `/examples`. For example, the latest interface takes a JSON as input which contains more information than the old interface. As a consequence, we no longer need to manually convert the input from string to `int` or raw hex, all we need now is a simple `reinterpret_cast`. The old application still works by taking all input as string but it's less efficient.

Navigate to the `build` directory to run the examples.

### Example 1: Edit Distance
Suppose we have `edit.wasm` either by compiling `/examples/edit_distance.cpp` or pick from `wasm/edit.wasm`. The arguments are `abcde` and `bcdef`, then:

```bash
./webgpu_prover '{"program":"../sdk/build/examples/edit.wasm","shader-path":"../shader","packing":8192,"private-indices":[1],"args":[{"str":"abcdeabcdeabcde"},{"str":"bcdefabcdeabcde"},{"i64":15},{"i64":15}]}'
```

This will run the Edit Distance program with the given packing size and arguments and verify that the edit distance between the two input strings `abcde` and `bcdef` is less than 5. The last two arguments are the length of the two input strings. You can run this code with two strings of arbitrary lengths. If you try to generate a proof with strings whose edit distance >= 5, the verification will fail.

For verification "private" arguments can be "obscured" as long as their input type is still correct and the argument length is the same:

```bash
./webgpu_verifier '{"program":"../sdk/build/examples/edit.wasm","shader-path":"../shader","packing":8192,"private-indices":[1],"args":[{"str":"xxxxxxxxxxxxxxx"},{"str":"bcdefabcdeabcde"},{"i64":15},{"i64":15}]}'
```

## Hardware Acceleration

Ligetron uses WebGPU (through Dawn or Emscripten) to accelerate the computation both natively and on browsers. Currently, we don't provide a fallback implementation if WebGPU is not available on your system. Technically, every device with the support of `DX12/Vulkan/Metal` should be able to run with the exception of iOS devices (specifically, iPhones).

On Linux, you might need additional flags to enable WebGPU support on browsers:

```bash
google-chrome --enable-unsafe-webgpu --enable-features=Vulkan
```

------

Copyright (C) 2023-2025 Ligero, Inc
