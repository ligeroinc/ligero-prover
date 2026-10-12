// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// Witness hints only: every imported value is checked by the pinned R1CS.
#pragma once
#include "circuit.hpp"
#include <fstream>
#include <limits>
#include <stdexcept>

namespace ecdsa_r1cs::witness {
using namespace ecdsa_r1cs;
inline constexpr uint32_t prefix_end = 4717, fixed_end = 88451, variable_end = 588332;
struct Part { uint32_t start; std::vector<Big> values; Point point; };
inline void u32(std::ostream& out, uint32_t value) {
    for (unsigned i=0;i<4;++i) out.put(char(value >> (8*i)));
}
inline uint32_t u32(std::istream& in) {
    uint32_t value=0;
    for (unsigned i=0;i<4;++i) { int byte=in.get(); if(byte<0) throw std::runtime_error("truncated witness part"); value |= uint32_t(byte)<<(8*i); }
    return value;
}
inline void integer(std::ostream& out, const Big& value) {
    if(value<0 || value >= (Big(1)<<256)) throw std::runtime_error("witness integer overflow");
    unsigned char bytes[32]{}; size_t count=0;
    mpz_export(bytes,&count,-1,1,0,0,value.get_mpz_t());
    out.write(reinterpret_cast<char*>(bytes),32);
}
inline Big integer(std::istream& in) {
    unsigned char bytes[32]; in.read(reinterpret_cast<char*>(bytes),32);
    if(!in) throw std::runtime_error("truncated witness integer");
    Big result; mpz_import(result.get_mpz_t(),32,-1,1,0,0,bytes); return result;
}
inline void expression(std::ostream& out,const LC& lc) {
    u32(out,static_cast<uint32_t>(lc.terms().size()));
    for(const auto& term:lc.terms()) {u32(out,term.wire);integer(out,term.coefficient);}
}
inline LC expression(std::istream& in,uint32_t limit) {
    const auto count=u32(in); if(count>4096) throw std::runtime_error("oversized witness expression");
    std::vector<Term> terms; terms.reserve(count);
    for(uint32_t i=0;i<count;++i) {const auto wire=u32(in);auto value=integer(in);if(wire>=limit || value>=native_modulus())throw std::runtime_error("invalid witness expression");terms.push_back({wire,std::move(value)});}
    return LC(std::move(terms));
}
inline void save(const Part& part,const std::string& path) {
    std::ofstream out(path,std::ios::binary);out.write("PWP1",4);u32(out,part.start);u32(out,part.values.size());
    for(const auto& value:part.values)integer(out,value);
    integer(out,part.point.value.x);integer(out,part.point.value.y);u32(out,part.point.value.infinity);
    for(const auto* number:{&part.point.x,&part.point.y})for(const auto& lc:number->limbs)expression(out,lc);
    expression(out,part.point.infinity);if(!out)throw std::runtime_error("cannot write witness part");
}
inline Part load(const std::string& path,uint32_t start,uint32_t end) {
    std::ifstream in(path,std::ios::binary);char magic[4];in.read(magic,4);
    if(!in || std::string(magic,4)!="PWP1" || u32(in)!=start || u32(in)!=end-start)throw std::runtime_error("witness part layout mismatch");
    Part part;part.start=start;part.values.reserve(end-start);
    for(uint32_t i=start;i<end;++i){auto v=integer(in);if(v>=native_modulus())throw std::runtime_error("noncanonical witness");part.values.push_back(std::move(v));}
    part.point.value.x=integer(in);part.point.value.y=integer(in);auto inf=u32(in);if(inf>1)throw std::runtime_error("invalid point hint");part.point.value.infinity=inf;
    part.point.x.value=part.point.value.x;part.point.y.value=part.point.value.y;
    for(auto* number:{&part.point.x,&part.point.y})for(auto& lc:number->limbs)lc=expression(in,end);
    part.point.infinity=expression(in,end);if(in.peek()!=std::char_traits<char>::eof())throw std::runtime_error("trailing witness data");
    return part;
}
inline PreparedEcdsa prepare(Builder& b,const Curve& curve,const std::array<Big,5>& input) {
    auto prepared=prepare_ecdsa(b,curve,input[4],input[2],input[3],{input[0],input[1],false});
    if(b.variables()!=prefix_end)throw std::runtime_error("ECDSA prefix layout changed");return prepared;
}
inline Part generate(unsigned kind,const std::array<Big,5>& input) {
    const auto curve=curve_by_name("secp256k1");Builder b(Builder::Mode::WitnessOnly);
    const auto p=prepare(b,curve,input);CurveCircuit ec(b,curve);ForeignField scalars(b,curve.n);
    Part result;
    if(kind==0){result.start=prefix_end;result.point=ec.fixed_mul(p.u1);if(b.variables()!=fixed_end)throw std::runtime_error("fixed witness layout changed");}
    else if(kind==1){b.pad_witness_values(fixed_end);result.start=fixed_end;result.point=ec.variable_mul(p.u2,p.q,scalars);if(b.variables()!=variable_end)throw std::runtime_error("variable witness layout changed");}
    else throw std::runtime_error("unknown witness part");
    const auto& values=b.witness_values();result.values.assign(values.begin()+result.start,values.end());return result;
}
inline void merge(Builder& b,const Curve& curve,const PreparedEcdsa& p,const Part& fixed,const Part& variable) {
    if(b.variables()!=prefix_end || fixed.start!=prefix_end || fixed.values.size()!=fixed_end-prefix_end || variable.start!=fixed_end || variable.values.size()!=variable_end-fixed_end)throw std::runtime_error("witness merge layout mismatch");
    b.append_witness_values(fixed.values);b.append_witness_values(variable.values);
    finish_ecdsa(b,curve,fixed.point,variable.point,p.r);
    if(b.variables()!=591290)throw std::runtime_error("final witness layout changed");
}
} // namespace ecdsa_r1cs::witness
