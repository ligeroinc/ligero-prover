# Ligetron SDK

## Build the SDK

To build the Ligetron SDK, you will need to [download and install](https://emscripten.org/docs/getting_started/downloads.html) `Emscripten`.

```bash
cd emsdk
source emsdk_env.sh
```

```bash
cd ligetron/sdk/cpp
mkdir build && cd build
emcmake cmake ..
make -j
```

## Build custom code

ZK applications in sdk/examples will be built automatically as part of the main SDK build. 
In addition, you can use ' Emscripten ' and the Ligetron SDK to build a custom application. For example, here is the command to build "my_custom_code.cpp":

```bash
em++ -O2 -I<path to SDK>/include -L<path to SDK>/build my_custom_code.cpp -o my_custom_code.wasm -lligetron
```
