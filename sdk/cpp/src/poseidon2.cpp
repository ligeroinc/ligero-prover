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

#include <memory>
#include <ligetron/poseidon2.h>

namespace ligetron {

/*************************************************************
 * Poseidon2 Instances
 * t = 2
 * ------------------------------------------------------------
 * External MDS (full round)    = [2, 1]
 *                                [1, 2]
 * Internal MDS (partial round) = [2, 1]
 *                                [1, 3]
 *************************************************************/

static void __pow5_inplace(bn254fr_class& in, bn254fr_class& tmp) {
    mulmod(tmp, in, in);   // tmp = x^2
    mulmod(tmp, tmp, tmp); // tmp = x^4
    mulmod(in, tmp, in);
}

static void __poseidon2_t2_multiply_external_MDS(bn254fr_class* state, bn254fr_class& sum) {
    addmod(sum, state[0], state[1]);
    addmod(state[0], sum, state[0]);
    addmod(state[1], sum, state[1]);
}

static void __poseidon2_t2_multiply_internal_MDS(bn254fr_class* state, bn254fr_class& sum) {
    addmod(sum, state[0], state[1]);
    addmod(state[0], sum, state[0]);
    addmod(sum, sum, state[1]);
    addmod(state[1], sum, state[1]);
}



static void __vpow5_inplace(vbn254fr_class& in, vbn254fr_class& tmp) {
    mulmod(tmp, in, in);   // tmp = x^2
    mulmod(tmp, tmp, tmp); // tmp = x^4
    mulmod(in, tmp, in);
}

static void __poseidon2_t2_multiply_external_MDS(vbn254fr_class *state, vbn254fr_class& sum) {
    addmod(sum, state[0], state[1]);
    addmod(state[0], sum, state[0]);
    addmod(state[1], sum, state[1]);
}

static void __poseidon2_t2_multiply_internal_MDS(vbn254fr_class *state, vbn254fr_class& sum) {
    addmod(sum, state[0], state[1]);
    addmod(state[0], sum, state[0]);
    addmod(sum, sum, state[1]);
    addmod(state[1], sum, state[1]);
}

// ------------------------------------------------------------


poseidon2_bn254_context *poseidon2_bn254_context_new() {
    poseidon2_bn254_context *ctx = new poseidon2_bn254_context;
    for (size_t i = 0; i < POSEIDON2_BN254_T2_RC_LEN; i++) {
        ctx->rc[i].set_str(poseidon2_t2_rc_str[i], 0);
    }
    return ctx;
}

void poseidon2_bn254_context_free(poseidon2_bn254_context *ctx) {
    delete ctx;
}

static void poseidon2_bn254_permute(poseidon2_bn254_context *ctx) {
    __poseidon2_t2_multiply_external_MDS(ctx->state, ctx->_tmp);

    int rounds = 0;
    for (int i = 0; i < 4; i++, rounds++) {
        addmod(ctx->state[0], ctx->state[0], ctx->rc[rounds * 2]);
        addmod(ctx->state[1], ctx->state[1], ctx->rc[rounds * 2 + 1]);

        __pow5_inplace(ctx->state[0], ctx->_tmp);
        __pow5_inplace(ctx->state[1], ctx->_tmp);

        __poseidon2_t2_multiply_external_MDS(ctx->state, ctx->_tmp);
    }

    for (int i = 0; i < 56; i++, rounds++) {
        addmod(ctx->state[0], ctx->state[0], ctx->rc[rounds * 2]);
        __pow5_inplace(ctx->state[0], ctx->_tmp);
        __poseidon2_t2_multiply_internal_MDS(ctx->state, ctx->_tmp);
    }

    for (int i = 0; i < 4; i++, rounds++) {
        addmod(ctx->state[0], ctx->state[0], ctx->rc[rounds * 2]);
        addmod(ctx->state[1], ctx->state[1], ctx->rc[rounds * 2 + 1]);

        __pow5_inplace(ctx->state[0], ctx->_tmp);
        __pow5_inplace(ctx->state[1], ctx->_tmp);

        __poseidon2_t2_multiply_external_MDS(ctx->state, ctx->_tmp);
    }
}

void poseidon2_bn254_digest_init(poseidon2_bn254_context *ctx) {
    ctx->state[0].set_u32(0u);
    ctx->state[1].set_u32(0u);
    std::memset(ctx->buf, 0, 31);
    ctx->len = 0;
}

void poseidon2_bn254_digest_update(poseidon2_bn254_context *ctx, bn254fr_class& msg) {
    addmod(ctx->state[0], ctx->state[0], msg);
    poseidon2_bn254_permute(ctx);
}

void poseidon2_bn254_digest_update_bytes(poseidon2_bn254_context *ctx, const unsigned char *in, uint32_t len) {
    int offset;
    for (offset = 0; len >= 31; len -= 31, offset += 31) {
        ctx->_tmp.set_bytes_big(in + offset, 31);
        poseidon2_bn254_digest_update(ctx, ctx->_tmp);
    }

    for (uint32_t i = 0; i < len; i++) {
        ctx->buf[ctx->len++] = in[offset + i];

        if (ctx->len >= 31) {
            ctx->_tmp.set_bytes_big(ctx->buf, 31);
            poseidon2_bn254_digest_update(ctx, ctx->_tmp);
            ctx->len = 0;
        }
    }
}

void poseidon2_bn254_digest_final(poseidon2_bn254_context *ctx, bn254fr_class& out) {
    ctx->buf[ctx->len++] = 0x80;
    for (; ctx->len < 31; ctx->len++) {
        ctx->buf[ctx->len] = 0;
    }

    ctx->_tmp.set_bytes_big(ctx->buf, 31);
    poseidon2_bn254_digest_update(ctx, ctx->_tmp);
    out = ctx->state[0];
}

// ------------------------------------------------------------

poseidon2_vbn254_context *poseidon2_vbn254_context_new() {
    poseidon2_vbn254_context *ctx = new poseidon2_vbn254_context;
    for (size_t i = 0; i < POSEIDON2_BN254_T2_RC_LEN; i++) {
        ctx->rc[i].set_str_scalar(poseidon2_t2_rc_str[i]);
    }
    return ctx;
}

void poseidon2_vbn254_context_free(poseidon2_vbn254_context *ctx) {
    delete ctx;
}

static void poseidon2_vbn254_permute(poseidon2_vbn254_context *ctx) {    
    __poseidon2_t2_multiply_external_MDS(ctx->state, ctx->_tmp);

    int rounds = 0;
    for (int i = 0; i < 4; i++, rounds++) {
        addmod(ctx->state[0], ctx->state[0], ctx->rc[rounds * 2]);
        addmod(ctx->state[1], ctx->state[1], ctx->rc[rounds * 2 + 1]);

        __vpow5_inplace(ctx->state[0], ctx->_tmp);
        __vpow5_inplace(ctx->state[1], ctx->_tmp);

        __poseidon2_t2_multiply_external_MDS(ctx->state, ctx->_tmp);
    }

    for (int i = 0; i < 56; i++, rounds++) {
        addmod(ctx->state[0], ctx->state[0], ctx->rc[rounds * 2]);
        __vpow5_inplace(ctx->state[0], ctx->_tmp);
        __poseidon2_t2_multiply_internal_MDS(ctx->state, ctx->_tmp);
    }

    for (int i = 0; i < 4; i++, rounds++) {
        addmod(ctx->state[0], ctx->state[0], ctx->rc[rounds * 2]);
        addmod(ctx->state[1], ctx->state[1], ctx->rc[rounds * 2 + 1]);

        __vpow5_inplace(ctx->state[0], ctx->_tmp);
        __vpow5_inplace(ctx->state[1], ctx->_tmp);

        __poseidon2_t2_multiply_external_MDS(ctx->state, ctx->_tmp);
    }
}

void poseidon2_vbn254_digest_init(poseidon2_vbn254_context *ctx) {
    ctx->state[0].set_ui_scalar(0u);
    ctx->state[1].set_ui_scalar(0u);
    std::memset(ctx->buf, 0, 31);
    ctx->len = 0;
}

void poseidon2_vbn254_digest_update(poseidon2_vbn254_context *ctx, const vbn254fr_class& msg) {
    addmod(ctx->state[0], ctx->state[0], msg);
    poseidon2_vbn254_permute(ctx);
}

void poseidon2_vbn254_digest_update_bytes(poseidon2_vbn254_context *ctx, const unsigned char *in, uint32_t len) {
    int offset;
    for (offset = 0; len >= 31; len -= 31, offset += 31) {
        ctx->_tmp.set_bytes_scalar(in + offset, 31);
        poseidon2_vbn254_digest_update(ctx, ctx->_tmp);
    }

    for (uint32_t i = 0; i < len; i++) {
        ctx->buf[ctx->len++] = in[offset + i];

        if (ctx->len >= 31) {
            ctx->_tmp.set_bytes_scalar(ctx->buf, 31);
            poseidon2_vbn254_digest_update(ctx, ctx->_tmp);
            ctx->len = 0;
        }
    }
}

void poseidon2_vbn254_digest_final(poseidon2_vbn254_context *ctx, vbn254fr_class& out) {
    ctx->buf[ctx->len++] = 0x80;
    for (; ctx->len < 31; ctx->len++) {
        ctx->buf[ctx->len] = 0;
    }

    ctx->_tmp.set_bytes_scalar(ctx->buf, 31);
    poseidon2_vbn254_digest_update(ctx, ctx->_tmp);
    out = ctx->state[0];
}

const char *poseidon2_t2_rc_str[(POSEIDON2_BN254_Rf + POSEIDON2_BN254_Rp) * 2] {
    "0x09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a7",
    "0x0c0356530896eec42a97ed937f3135cfc5142b3ae405b8343c1d83ffa604cb81",
    "0x1e28a1d935698ad1142e51182bb54cf4a00ea5aabd6268bd317ea977cc154a30",
    "0x27af2d831a9d2748080965db30e298e40e5757c3e008db964cf9e2b12b91251f",
    "0x1e6f11ce60fc8f513a6a3cfe16ae175a41291462f214cd0879aaf43545b74e03",
    "0x2a67384d3bbd5e438541819cb681f0be04462ed14c3613d8f719206268d142d3",
    "0x0b66fdf356093a611609f8e12fbfecf0b985e381f025188936408f5d5c9f45d0",
    "0x012ee3ec1e78d470830c61093c2ade370b26c83cc5cebeeddaa6852dbdb09e21",
    "0x0252ba5f6760bfbdfd88f67f8175e3fd6cd1c431b099b6bb2d108e7b445bb1b9",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x179474cceca5ff676c6bec3cef54296354391a8935ff71d6ef5aeaad7ca932f1",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x2c24261379a51bfa9228ff4a503fd4ed9c1f974a264969b37e1a2589bbed2b91",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1cc1d7b62692e63eac2f288bd0695b43c2f63f5001fc0fc553e66c0551801b05",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x255059301aada98bb2ed55f852979e9600784dbf17fbacd05d9eff5fd9c91b56",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x28437be3ac1cb2e479e1f5c0eccd32b3aea24234970a8193b11c29ce7e59efd9",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x28216a442f2e1f711ca4fa6b53766eb118548da8fb4f78d4338762c37f5f2043",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x2c1f47cd17fa5adf1f39f4e7056dd03feee1efce03094581131f2377323482c9",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x07abad02b7a5ebc48632bcc9356ceb7dd9dafca276638a63646b8566a621afc9",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0230264601ffdf29275b33ffaab51dfe9429f90880a69cd137da0c4d15f96c3c",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1bc973054e51d905a0f168656497ca40a864414557ee289e717e5d66899aa0a9",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x2e1c22f964435008206c3157e86341edd249aff5c2d8421f2a6b22288f0a67fc",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1224f38df67c5378121c1d5f461bbc509e8ea1598e46c9f7a70452bc2bba86b8",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x02e4e69d8ba59e519280b4bd9ed0068fd7bfe8cd9dfeda1969d2989186cde20e",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1f1eccc34aaba0137f5df81fc04ff3ee4f19ee364e653f076d47e9735d98018e",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1672ad3d709a353974266c3039a9a7311424448032cd1819eacb8a4d4284f582",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x283e3fdc2c6e420c56f44af5192b4ae9cda6961f284d24991d2ed602df8c8fc7",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1c2a3d120c550ecfd0db0957170fa013683751f8fdff59d6614fbd69ff394bcc",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x216f84877aac6172f7897a7323456efe143a9a43773ea6f296cb6b8177653fbd",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x2c0d272becf2a75764ba7e8e3e28d12bceaa47ea61ca59a411a1f51552f94788",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x16e34299865c0e28484ee7a74c454e9f170a5480abe0508fcb4a6c3d89546f43",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x175ceba599e96f5b375a232a6fb9cc71772047765802290f48cd939755488fc5",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0c7594440dc48c16fead9e1758b028066aa410bfbc354f54d8c5ffbb44a1ee32",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1a3c29bc39f21bb5c466db7d7eb6fd8f760e20013ccf912c92479882d919fd8d",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0ccfdd906f3426e5c0986ea049b253400855d349074f5a6695c8eeabcd22e68f",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x14f6bc81d9f186f62bdb475ce6c9411866a7a8a3fd065b3ce0e699b67dd9e796",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0962b82789fb3d129702ca70b2f6c5aacc099810c9c495c888edeb7386b97052",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1a880af7074d18b3bf20c79de25127bc13284ab01ef02575afef0c8f6a31a86d",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x10cba18419a6a332cd5e77f0211c154b20af2924fc20ff3f4c3012bb7ae9311b",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x057e62a9a8f89b3ebdc76ba63a9eaca8fa27b7319cae3406756a2849f302f10d",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x287c971de91dc0abd44adf5384b4988cb961303bbf65cff5afa0413b44280cee",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x21df3388af1687bbb3bca9da0cca908f1e562bc46d4aba4e6f7f7960e306891d",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1be5c887d25bce703e25cc974d0934cd789df8f70b498fd83eff8b560e1682b3",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x268da36f76e568fb68117175cea2cd0dd2cb5d42fda5acea48d59c2706a0d5c1",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0e17ab091f6eae50c609beaf5510ececc5d8bb74135ebd05bd06460cc26a5ed6",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x04d727e728ffa0a67aee535ab074a43091ef62d8cf83d270040f5caa1f62af40",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0ddbd7bf9c29341581b549762bc022ed33702ac10f1bfd862b15417d7e39ca6e",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x2790eb3351621752768162e82989c6c234f5b0d1d3af9b588a29c49c8789654b",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1e457c601a63b73e4471950193d8a570395f3d9ab8b2fd0984b764206142f9e9",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x21ae64301dca9625638d6ab2bbe7135ffa90ecd0c43ff91fc4c686fc46e091b0",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0379f63c8ce3468d4da293166f494928854be9e3432e09555858534eed8d350b",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x002d56420359d0266a744a080809e054ca0e4921a46686ac8c9f58a324c35049",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x123158e5965b5d9b1d68b3cd32e10bbeda8d62459e21f4090fc2c5af963515a6",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0be29fc40847a941661d14bbf6cbe0420fbb2b6f52836d4e60c80eb49cad9ec1",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1ac96991dec2bb0557716142015a453c36db9d859cad5f9a233802f24fdf4c1a",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1596443f763dbcc25f4964fc61d23b3e5e12c9fa97f18a9251ca3355bcb0627e",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x12e0bcd3654bdfa76b2861d4ec3aeae0f1857d9f17e715aed6d049eae3ba3212",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0fc92b4f1bbea82b9ea73d4af9af2a50ceabac7f37154b1904e6c76c7cf964ba",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1f9c0b1610446442d6f2e592a8013f40b14f7c7722236f4f9c7e965233872762",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0ebd74244ae72675f8cde06157a782f4050d914da38b4c058d159f643dbbf4d3",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x2cb7f0ed39e16e9f69a9fafd4ab951c03b0671e97346ee397a839839dccfc6d1",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1a9d6e2ecff022cc5605443ee41bab20ce761d0514ce526690c72bca7352d9bf",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x2a115439607f335a5ea83c3bc44a9331d0c13326a9a7ba3087da182d648ec72f",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x23f9b6529b5d040d15b8fa7aee3e3410e738b56305cd44f29535c115c5a4c060",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x05872c16db0f72a2249ac6ba484bb9c3a3ce97c16d58b68b260eb939f0e6e8a7",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1300bdee08bb7824ca20fb80118075f40219b6151d55b5c52b624a7cdeddf6a7",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x19b9b63d2f108e17e63817863a8f6c288d7ad29916d98cb1072e4e7b7d52b376",
    "0x015bee1357e3c015b5bda237668522f613d1c88726b5ec4224a20128481b4f7f",
    "0x2953736e94bb6b9f1b9707a4f1615e4efe1e1ce4bab218cbea92c785b128ffd1",
    "0x0b069353ba091618862f806180c0385f851b98d372b45f544ce7266ed6608dfc",
    "0x304f74d461ccc13115e4e0bcfb93817e55aeb7eb9306b64e4f588ac97d81f429",
    "0x15bbf146ce9bca09e8a33f5e77dfe4f5aad2a164a4617a4cb8ee5415cde913fc",
    "0x0ab4dfe0c2742cde44901031487964ed9b8f4b850405c10ca9ff23859572c8c6",
    "0x0e32db320a044e3197f45f7649a19675ef5eedfea546dea9251de39f9639779a",
};

} // namespace ligetron