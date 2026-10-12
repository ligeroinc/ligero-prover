// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "witness_parts.hpp"
#include <chrono>
#include <iostream>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
extern "C" EMSCRIPTEN_KEEPALIVE int ligero_ecdsa_witness_prepare(int part) {
    try {
        if(part==0) {
            ecdsa_r1cs::Builder builder(ecdsa_r1cs::Builder::Mode::WitnessOnly);
            ecdsa_r1cs::CurveCircuit ec(builder,ecdsa_r1cs::curve_by_name("secp256k1"));
            ec.prepare_fixed_base_table();
        }
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
#endif
int main(int argc,char** argv) {
    try {
        if(argc!=7)throw std::runtime_error("expected part and five ECDSA components");
        std::array<ecdsa_r1cs::Big,5> input;for(unsigned i=0;i<5;++i)input[i]=ecdsa_r1cs::Big(argv[i+2],16);
        auto start=std::chrono::steady_clock::now();
        auto part=ecdsa_r1cs::witness::generate(std::stoul(argv[1]),input);
        ecdsa_r1cs::witness::save(part,"/witness-part.bin");
        std::cout<<"Witness part seconds: "<<std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count()<<'\n';
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
