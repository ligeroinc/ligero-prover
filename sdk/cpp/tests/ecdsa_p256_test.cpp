/*
 * Copyright (C) 2023-2026 Ligero, Inc.
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

#include <ligetron/ec/p256.hpp>
#include <ligetron/ec/ecdsa.hpp>
#include <vector>


using namespace ligetron;


unsigned char hex_char_to_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return 0xFF;
}

std::vector<unsigned char> hex_to_binary(const std::string &hex) {
    assert(hex.size() % 2 == 0 && "invalid hex data size");
    size_t n_bytes = hex.size() / 2;

    std::vector<unsigned char> res;
    res.reserve(n_bytes);

    for (size_t i = 0; i < n_bytes; ++i) {
        unsigned char byte = hex_char_to_val(hex[i * 2]) << 4;
        byte |= hex_char_to_val(hex[i * 2 + 1]);
        res.push_back(byte);
    }

    return res;
}

void test_ecdsa_p256(const std::string &pub_key_x_str,
                     const std::string &pub_key_y_str,
                     const std::string &msg_hash_hex,
                     const std::string &r_str,
                     const std::string &s_str) {

    auto msg_hash_data = hex_to_binary(msg_hash_hex);

    ec::p256_curve::scalar_field_element r{r_str.c_str()};
    ec::p256_curve::scalar_field_element s{s_str.c_str()};
    ec::p256_curve::point pub_key{pub_key_x_str.c_str(), pub_key_y_str.c_str()};

    assert_one(ecdsa_verify<ec::p256_curve>(msg_hash_data, r, s, pub_key));
}


int main(int argc, char * argv[]) {
    test_ecdsa_p256("0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
                    "0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
                    "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56",
                    "110216805958592777714039232774448176272891959258816807100364142388121497551532",
                    "63308726082909978129457058886438288747780283410792251258965605561145777031427");

    test_ecdsa_p256("0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
                    "0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
                    "545187fe6ca0e42034734aa8f2c0cb73aca71cbc978af9cf928a1ea48f21c857",
                    "0xf3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
                    "0xea2dfff3ffe27d569440b050a5daeaea6d3f53bb943fd063a23daf15b598758a");


    // Hash value greater than P256 base field prime
    test_ecdsa_p256("0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
                    "0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
                    "ffffffff00000001000000000000000000000002ffffffffffffffffffffffff",
                    "0xf3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
                    "0xe19b0d2e78488e2b6f7168645d1f7529008662819a2d684ca15166d3a5142aa9");


    // Test vectors from
    // https://boringssl.googlesource.com/boringssl/+/main/crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt

    test_ecdsa_p256("0x29578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab",
                    "0x08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800",
                    "5e53611194b517b0ef4f704684850dfa387f99997d586d43c9e41530",
                    "0x4a19274429e40522234b8785dc25fc524f179dcc95ff09b3c9770fc71f54ca0d",
                    "0x58982b79a65b7320f5b92d13bdaecdd1259e760f0f718ba933fd098f6f75d4b7");

    test_ecdsa_p256("0x4a92396ff7930b1da9a873a479a28a9896af6cc3d39345b949b726dc3cd978b5",
                    "0x475abb18eaed948879b9c1453e3ef2755dd90f77519ec7b6a30297aad08e4931",
                    "50be7b4f0e1fa36f06eb430ad4afe8f0cea2b97e060230f91ed1922b",
                    "0x38b29558511061cfabdc8e5bb65ac2976d1aa2ba9a5deab8074097b2172bb9ad",
                    "0x0de2cde610502b6e03c0b23602eafbcd3faf886c81d111d156b7aa550f5bcd51");

    test_ecdsa_p256("0x5775174deb0248112e069cb86f1546ac7a78bc2127d0cb953bad46384dd6be5b",
                    "0xa27020952971cc0b0c3abd06e9ca3e141a4943f560564eba31e5288928bc7ce7",
                    "f51177ab6c34bf80ea72d687a670e4102987d1378bd9a4d973af4dad",
                    "0xb02a440add66a9ff9c3c0e9acf1be678f6bd48a10cbdec2ad6d186ffe05f3f2a",
                    "0xa98bea42aec56a1fcecec00a1cc69b01fcbcf5de7ac1b2f2dcc09b6db064f92b");


    test_ecdsa_p256("0xf888e913ec6f3cd8b31eb89e4f8aaa8887d30ae5348ed7118696949d5b8cc7c1",
                    "0x08895d09620500d244e5035e262dea3f2867cd8967b226324d5c05220d8b410c",
                    "03bf686dab49196f887f3a8083f1a39e26085127a9d9e6a78f22f652",
                    "0x2e6cc883b8acc904ee9691ef4a9f1f5a9e5fbfde847cda3be833f949fb9c7182",
                    "0x2ac48f7a930912131a8b4e3ab495307817c465d638c2a9ea5ae9e2808806e20a");

    test_ecdsa_p256("0x137c465085c1b1b8cccbe9fccbe9d0295a331aaf332f3ed2e285d16e574b943b",
                    "0xd3e8d5a24cd218c19760b0e85b35a8569945aa857cbf0fd6a3ce127581b217b6",
                    "40a7ece19f7f6a6473b209a7ac9441d59b00fc94ae0ded3423427c12",
                    "0x775e25a296bd259510ae9375f548997bec8a744900022945281dc8c4d94f2b5b",
                    "0xd87592ceab773ae103daebbb56a04144aaccb1e14efc1024dc36c0e382df1f70");

    test_ecdsa_p256("0x82b1f1a7af9b48ca8452613d7032beb0e4f28fe710306aeccc959e4d03662a35",
                    "0x5e39f33574097b8d32b471a591972496f5d44db344c037d13f06fafc75f016fd",
                    "f6c083325d6316e337c102b16bb96faa478a43b2dc0d56d51a4affed",
                    "0xa754b42720e71925d51fcef76151405a3696cc8f9fc9ca7b46d0b16edd7fb699",
                    "0x603924780439cc16ac4cf97c2c3065bc95353aa9179d0ab5f0322ca82f851cf2");

    test_ecdsa_p256("0xe0bbfe4016eea93e6f509518cbffc25d492de6ebbf80465a461caa5bdc018159",
                    "0x3231ee7a119d84fa56e3034d50fea85929aec2eb437abc7646821e1bf805fb50",
                    "6890736262386d60424be27b3f95996ab696e1ddffdc4a03c256a7c0",
                    "0x96d1c9399948254ea381631fc0f43ea808110506db8aacf081df5535ac5eb8ad",
                    "0x73bf3691260dddd9997c97313f2a70783eacf8d15bdfb34bb13025cdfae72f70");

    test_ecdsa_p256("0xe3c58c1c254d11c7e781ad133e4c36dd1b5de362120d336a58e7b68813f3fbee",
                    "0x59760db66120afe0d962c81a8e5586588fd19de2f40556371611c73af22c8a68",
                    "e8ed2e73fe9e3c6bb087c5179bb357be4cd147bc66e70dc1fecc10fd",
                    "0x25dd8e4086c62a40d2a310e2f90f6af5cb7e677b4dfdb4dc4e99e23ea2f0e6dc",
                    "0x90ad62c179b0c9d61f521dde1cd762bfd224b5525c39c3706f2549313ddb4f39");

    test_ecdsa_p256("0xcb3634ec4f0cbb99986be788f889e586026d5a851e80d15382f1bdb1bda2bc75",
                    "0x51e4e43bc16fb114896b18198a1aebe6054ba20ed0c0317c1b8776158c0e6bfb",
                    "ca7e8c8c873346c85db9ac648509c8ccc9ab5651d91e35a248b951fb",
                    "0x261a1cdb0fd93c0fb06ea6068b6b03c330a12f621a7eba76682a1d152c0e8d08",
                    "0x7ca049bad54feee101d6db807635ffb8bdb05a38e445c8c3d65d60df143514c5");

    test_ecdsa_p256("0x7cca1334bfc2a78728c50b370399be3f9690d445aa03c701da643eeb0b0f7fa8",
                    "0x3f7522238668e615405e49b2f63faee58286000a30cdb4b564ac0df99bc8950f",
                    "3367c395a9ad7b8214c48658f2a4b377b6b0288ba272a4fbfeaa48df",
                    "0xa18194c7ac5829afc408d78dde19542837e7be82706c3941b2d9c5e036bb51e0",
                    "0x188ead1cdf7c1d21114ff56d0421ffd501ab978ef58337462c0fa736d86299af");

    test_ecdsa_p256("0x0aaeed6dd1ae020d6eefc98ec4241ac93cbd3c8afed05bb28007e7da5727571b",
                    "0x2dda1d5b7872eb94dfffb456115037ff8d3e72f8ebdd8fcfc42391f96809be69",
                    "a36a7d6424763633320ca799667f1b79955f079fb1b6dc264058af41",
                    "0x8cb9f41dfdcb9604e0725ac9b78fc0db916dc071186ee982f6dba3da36f02efa",
                    "0x5c87fe868fd4282fb114f5d70e9590a10a5d35cedf3ff6402ba5c4344738a32e");

    test_ecdsa_p256("0xc227a2af15dfa8734e11c0c50f77e24e77ed58dd8cccf1b0e9fa06bee1c64766",
                    "0xb686592ce3745eb300d2704083db55e1fa8274e4cb7e256889ccc0bb34a60570",
                    "864f18aa83fd3af6cdf6ac7f8526062d0c48a8d3c341cc23d53be864",
                    "0x5e89d3c9b103c2fa3cb8cebeec23640acda0257d63ffbe2d509bfc49fab1dca6",
                    "0xd70c5b1eeb29e016af9925798d24e166c23d58fedd2f1a3bbdb1ef78cdbfb63a");

    test_ecdsa_p256("0x722e0abad4504b7832a148746153777694714eca220eced2b2156ca64cfed3dd",
                    "0xf0351b357b3081e859c46cad5328c5afa10546e92bc6c3fd541796ac30397a75",
                    "916924fcced069bf6956eeb4e8f09dc9bf928e8a690111b699e39eab",
                    "0x9d086dcd22da165a43091991bede9c1c14515e656633cb759ec2c17f51c35253",
                    "0x23595ad1cb714559faaecaf946beb9a71e584616030ceaed8a8470f4bf62768f");

    test_ecdsa_p256("0x4814d454495df7103e2da383aba55f7842fd84f1750ee5801ad32c10d0be6c7d",
                    "0xa0bd039d5097c8f0770477f6b18d247876e88e528bf0453eab515ffab8a9eda3",
                    "ec2fb907b92865e501ce97f703cf6214a6de2303df472ba58145af16",
                    "0x84db02c678f9a21208cec8564d145a35ba8c6f26b4eb7e19522e439720dae44c",
                    "0x537c564da0d2dc5ac4376c5f0ca3b628d01d48df47a83d842c927e4d6db1e16d");

    test_ecdsa_p256("0xf04e9f2831d9697ae146c7d4552e5f91085cc46778400b75b76f00205252941d",
                    "0xbd267148174cd0c2b019cd0a5256e2f3f889d1e597160372b5a1339c8d787f10",
                    "b047a2a715335a1cc255beb983355e7d1363c610bf56df45d4503e69",
                    "0x5d95c385eeba0f15db0b80ae151912409128c9c80e554246067b8f6a36d85ea5",
                    "0xdb5d8a1e345f883e4fcb3871276f170b783c1a1e9da6b6615913368a8526f1c3");

    test_ecdsa_p256("0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
                    "0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
                    "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56",
                    "0xf3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
                    "0x8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903");

    test_ecdsa_p256("0xe266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8a",
                    "0xbfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39",
                    "9b2db89cb0e8fa3cc7608b4d6cc1dec0114e0b9ff4080bea12b134f489ab2bbc",
                    "0x976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db",
                    "0x1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932");

    test_ecdsa_p256("0x74ccd8a62fba0e667c50929a53f78c21b8ff0c3c737b0b40b1750b2302b0bde8",
                    "0x29074e21f3a0ef88b9efdf10d06aa4c295cc1671f758ca0e4cd108803d0f2614",
                    "b804cf88af0c2eff8bbbfb3660ebb3294138e9d3ebd458884e19818061dacff0",
                    "0x35fb60f5ca0f3ca08542fb3cc641c8263a2cab7a90ee6a5e1583fac2bb6f6bd1",
                    "0xee59d81bc9db1055cc0ed97b159d8784af04e98511d0a9a407b99bb292572e96");

    test_ecdsa_p256("0x322f80371bf6e044bc49391d97c1714ab87f990b949bc178cb7c43b7c22d89e1",
                    "0x3c15d54a5cc6b9f09de8457e873eb3deb1fceb54b0b295da6050294fae7fd999",
                    "85b957d92766235e7c880ac5447cfbe97f3cb499f486d1e43bcb5c2ff9608a1a",
                    "0xd7c562370af617b581c84a2468cc8bd50bb1cbf322de41b7887ce07c0e5884ca",
                    "0xb46d9f2d8c4bf83546ff178f1d78937c008d64e8ecc5cbb825cb21d94d670d89");

    test_ecdsa_p256("0x1bcec4570e1ec2436596b8ded58f60c3b1ebc6a403bc5543040ba82963057244",
                    "0x8af62a4c683f096b28558320737bf83b9959a46ad2521004ef74cf85e67494e1",
                    "3360d699222f21840827cf698d7cb635bee57dc80cd7733b682d41b55b666e22",
                    "0x18caaf7b663507a8bcd992b836dec9dc5703c080af5e51dfa3a9a7c387182604",
                    "0x77c68928ac3b88d985fb43fb615fb7ff45c18ba5c81af796c613dfa98352d29c");

    test_ecdsa_p256("0xa32e50be3dae2c8ba3f5e4bdae14cf7645420d425ead94036c22dd6c4fc59e00",
                    "0xd623bf641160c289d6742c6257ae6ba574446dd1d0e74db3aaa80900b78d4ae9",
                    "c413c4908cd0bc6d8e32001aa103043b2cf5be7fcbd61a5cec9488c3a577ca57",
                    "0x8524c5024e2d9a73bde8c72d9129f57873bbad0ed05215a372a84fdbc78f2e68",
                    "0xd18c2caf3b1072f87064ec5e8953f51301cada03469c640244760328eb5a05cb");

    test_ecdsa_p256("0x8bcfe2a721ca6d753968f564ec4315be4857e28bef1908f61a366b1f03c97479",
                    "0x0f67576a30b8e20d4232d8530b52fb4c89cbc589ede291e499ddd15fe870ab96",
                    "88fc1e7d849794fc51b135fa135deec0db02b86c3cd8cebdaa79e8689e5b2898",
                    "0xc5a186d72df452015480f7f338970bfe825087f05c0088d95305f87aacc9b254",
                    "0x84a58f9e9d9e735344b316b1aa1ab5185665b85147dc82d92e969d7bee31ca30");

    test_ecdsa_p256("0xa88bc8430279c8c0400a77d751f26c0abc93e5de4ad9a4166357952fe041e767",
                    "0x2d365a1eef25ead579cc9a069b6abc1b16b81c35f18785ce26a10ba6d1381185",
                    "41fa8d8b4cd0a5fdf021f4e4829d6d1e996bab6b4a19dcb85585fe76c582d2bc",
                    "0x9d0c6afb6df3bced455b459cc21387e14929392664bb8741a3693a1795ca6902",
                    "0xd7f9ddd191f1f412869429209ee3814c75c72fa46a9cccf804a2f5cc0b7e739f");

    test_ecdsa_p256("0x1bc487570f040dc94196c9befe8ab2b6de77208b1f38bdaae28f9645c4d2bc3a",
                    "0xec81602abd8345e71867c8210313737865b8aa186851e1b48eaca140320f5d8f",
                    "2d72947c1731543b3d62490866a893952736757746d9bae13e719079299ae192",
                    "0x2f9e2b4e9f747c657f705bffd124ee178bbc5391c86d056717b140c153570fd9",
                    "0xf5413bfd85949da8d83de83ab0d19b2986613e224d1901d76919de23ccd03199");

    test_ecdsa_p256("0xb8188bd68701fc396dab53125d4d28ea33a91daf6d21485f4770f6ea8c565dde",
                    "0x423f058810f277f8fe076f6db56e9285a1bf2c2a1dae145095edd9c04970bc4a",
                    "e138bd577c3729d0e24a98a82478bcc7482499c4cdf734a874f7208ddbc3c116",
                    "0x1cc628533d0004b2b20e7f4baad0b8bb5e0673db159bbccf92491aef61fc9620",
                    "0x880e0bbf82a8cf818ed46ba03cf0fc6c898e36fca36cc7fdb1d2db7503634430");

    test_ecdsa_p256("0x51f99d2d52d4a6e734484a018b7ca2f895c2929b6754a3a03224d07ae61166ce",
                    "0x4737da963c6ef7247fb88d19f9b0c667cac7fe12837fdab88c66f10d3c14cad1",
                    "17b03f9f00f6692ccdde485fc63c4530751ef35da6f71336610944b0894fcfb8",
                    "0x9886ae46c1415c3bc959e82b760ad760aab66885a84e620aa339fdf102465c42",
                    "0x2bf3a80bc04faa35ebecc0f4864ac02d349f6f126e0f988501b8d3075409a26c");

    test_ecdsa_p256("0x8fb287f0202ad57ae841aea35f29b2e1d53e196d0ddd9aec24813d64c0922fb7",
                    "0x1f6daff1aa2dd2d6d3741623eecb5e7b612997a1039aab2e5cf2de969cfea573",
                    "c25beae638ff8dcd370e03a6f89c594c55bed1277ee14d83bbb0ef783a0517c7",
                    "0x490efd106be11fc365c7467eb89b8d39e15d65175356775deab211163c2504cb",
                    "0x644300fc0da4d40fb8c6ead510d14f0bd4e1321a469e9c0a581464c7186b7aa7");

    test_ecdsa_p256("0x68229b48c2fe19d3db034e4c15077eb7471a66031f28a980821873915298ba76",
                    "0x303e8ee3742a893f78b810991da697083dd8f11128c47651c27a56740a80c24c",
                    "5eb28029ebf3c7025ff2fc2f6de6f62aecf6a72139e1cba5f20d11bbef036a7f",
                    "0xe67a9717ccf96841489d6541f4f6adb12d17b59a6bef847b6183b8fcf16a32eb",
                    "0x9ae6ba6d637706849a6a9fc388cf0232d85c26ea0d1fe7437adb48de58364333");

    test_ecdsa_p256("0x0a7dbb8bf50cb605eb2268b081f26d6b08e012f952c4b70a5a1e6e7d46af98bb",
                    "0xf26dd7d799930062480849962ccf5004edcfd307c044f4e8f667c9baa834eeae",
                    "12135386c09e0bf6fd5c454a95bcfe9b3edb25c71e455c73a212405694b29002",
                    "0xb53ce4da1aa7c0dc77a1896ab716b921499aed78df725b1504aba1597ba0c64b",
                    "0xd7c246dc7ad0e67700c373edcfdd1c0a0495fc954549ad579df6ed1438840851");

    test_ecdsa_p256("0x105d22d9c626520faca13e7ced382dcbe93498315f00cc0ac39c4821d0d73737",
                    "0x6c47f3cbbfa97dfcebe16270b8c7d5d3a5900b888c42520d751e8faf3b401ef4",
                    "aea3e069e03c0ff4d6b3fa2235e0053bbedc4c7e40efbc686d4dfb5efba4cfed",
                    "0x542c40a18140a6266d6f0286e24e9a7bad7650e72ef0e2131e629c076d962663",
                    "0x4f7f65305e24a6bbb5cff714ba8f5a2cee5bdc89ba8d75dcbf21966ce38eb66f");

    test_ecdsa_p256("0xe0e7b99bc62d8dd67883e39ed9fa0657789c5ff556cc1fd8dd1e2a55e9e3f243",
                    "0x63fbfd0232b95578075c903a4dbf85ad58f8350516e1ec89b0ee1f5e1362da69",
                    "d9c83b92fa0979f4a5ddbd8dd22ab9377801c3c31bf50f932ace0d2146e2574da0d5552dbed4b18836280e9f94558ea6",
                    "0xf5087878e212b703578f5c66f434883f3ef414dc23e2e8d8ab6a8d159ed5ad83",
                    "0x306b4c6c20213707982dffbb30fba99b96e792163dd59dbe606e734328dd7c8a");

    test_ecdsa_p256("0xafda82260c9f42122a3f11c6058839488f6d7977f6f2a263c67d06e27ea2c355",
                    "0x0ae2bbdd2207c590332c5bfeb4c8b5b16622134bd4dc55382ae806435468058b",
                    "76c8df4563375d34656f2d1dd3445c9d9f0c8da59dc015fa6122237e1a02039998c16b3935e281160923c6e21115d0a9",
                    "0xe446600cab1286ebc3bb332012a2f5cc33b0a5ef7291d5a62a84de5969d77946",
                    "0xcf89b12793ee1792eb26283b48fa0bdcb45ae6f6ad4b02564bf786bb97057d5a");

    test_ecdsa_p256("0x702b2c94d039e590dd5c8f9736e753cf5824aacf33ee3de74fe1f5f7c858d5ed",
                    "0x0c28894e907af99fb0d18c9e98f19ac80dd77abfa4bebe45055c0857b82a0f4d",
                    "bad1b2c4c35c54eede5d9dee6f6821bb0254395ae6a689ae7289790448ff787ea4e495ea418c0759c51144a74eba3ac9",
                    "0xc4021fb7185a07096547af1fb06932e37cf8bd90cf593dea48d48614fa237e5e",
                    "0x7fb45d09e2172bec8d3e330aa06c43fbb5f625525485234e7714b7f6e92ba8f1");

    test_ecdsa_p256("0xd12512e934c367e4c4384dbd010e93416840288a0ba00b299b4e7c0d91578b57",
                    "0xebf8835661d9b578f18d14ae4acf9c357c0dc8b7112fc32824a685ed72754e23",
                    "c248cc5eb23ed0f6f03de308fffed1e5fdd918aef379946d7b66b8924dc38306feb28e85cc5ab5d7a3a0e55087ddecde",
                    "0x4d5a9d95b0f09ce8704b0f457b39059ee606092310df65d3f8ae7a2a424cf232",
                    "0x7d3c014ca470a73cef1d1da86f2a541148ad542fbccaf9149d1b0b030441a7eb");

    test_ecdsa_p256("0xb4238b029fc0b7d9a5286d8c29b6f3d5a569e9108d44d889cd795c4a385905be",
                    "0x8cb3fff8f6cca7187c6a9ad0a2b1d9f40ae01b32a7e8f8c4ca75d71a1fffb309",
                    "b05d944f6752bfe003526499bb4d8721c0d25a7901999f67519b17665e907cd148b2ff1b451248d292866bcc81b506d9",
                    "0x26fd9147d0c86440689ff2d75569795650140506970791c90ace0924b44f1586",
                    "0x00a34b00c20a8099df4b0a757cbef8fea1cb3ea7ced5fbf7e987f70b25ee6d4f");

    test_ecdsa_p256("0xc3bdc7c795ec94620a2cfff614c13a3390a5e86c892e53a24d3ed22228bc85bf",
                    "0x70480fc5cf4aacd73e24618b61b5c56c1ced8c4f1b869580ea538e68c7a61ca3",
                    "847325a13b72de5a15cd899ced0920b8543ab26f9d3877fde99c5018efc78ddf14c00f88b06af7971181923aa46624d4",
                    "0xa860c8b286edf973ce4ce4cf6e70dc9bbf3818c36c023a845677a9963705df8b",
                    "0x5630f986b1c45e36e127dd7932221c4272a8cc6e255e89f0f0ca4ec3a9f76494");

    test_ecdsa_p256("0x8d40bf2299e05d758d421972e81cfb0cce68b949240dc30f315836acc70bef03",
                    "0x5674e6f77f8b46f46cca937d83b128dffbe9bd7e0d3d08aa2cbbfdfb16f72c9a",
                    "fd30608cf408dac5886ca156bdce7f75067e18172af79ca84f8d60d011b8a6b5ea33a92554d1ea34b105d5bd09062d47",
                    "0xef6fb386ad044b63feb7445fa16b10319018e9cea9ef42bca83bdad01992234a",
                    "0xac1f42f652eb1786e57be01d847c81f7efa072ba566d4583af4f1551a3f76c65");

    test_ecdsa_p256("0x660da45c413cc9c9526202c16b402af602d30daaa7c342f1e722f15199407f31",
                    "0xe6f8cbb06913cc718f2d69ba2fb3137f04a41c27c676d1a80fbf30ea3ca46439",
                    "9d21e70e88c43cbab056c5fdeb63baa2660ebc44e0d1ef781f8f6bf58b28e3a2c9d5db051c8da3ba34796d8bcc7ba5cb",
                    "0x08fabf9b57de81875bfa7a4118e3e44cfb38ec6a9b2014940207ba3b1c583038",
                    "0xa58d199b1deba7350616230d867b2747a3459421811c291836abee715b8f67b4");

    test_ecdsa_p256("0xb4909a5bdf25f7659f4ef35e4b811429fb2c59126e3dad09100b46aea6ebe7a6",
                    "0x760ae015fa6af5c9749c4030fdb5de6e58c6b5b1944829105cf7edf7d3a22cfb",
                    "0bc6a254fa0016a5aa608309f9a97cf0c879370bae0b7b460da17c2694e8414db39ec8b5f943167372610fc146dd8b28",
                    "0x6ec9a340b77fae3c7827fa96d997e92722ff2a928217b6dd3c628f3d49ae4ce6",
                    "0x637b54bbcfb7e7d8a41ea317fcfca8ad74eb3bb6b778bc7ef9dec009281976f7");

    test_ecdsa_p256("0xc786d9421d67b72b922cf3def2a25eeb5e73f34543eb50b152e738a98afb0ca5",
                    "0x6796271e79e2496f9e74b126b1123a3d067de56b5605d6f51c8f6e1d5bb93aba",
                    "12520a7ef4f05f91b9f9a0fba73eddc813413c4d4764dc1c4b773c4afd5cd77b0e7f09d56e5931aec2958407c02774c0",
                    "0x07e5054c384839584624e8d730454dc27e673c4a90cbf129d88b91250341854d",
                    "0xf7e665b88614d0c5cbb3007cafe713763d81831525971f1747d92e4d1ca263a7");

    test_ecdsa_p256("0x86662c014ab666ee770723be8da38c5cd299efc6480fc6f8c3603438fa8397b9",
                    "0xf26b3307a650c3863faaa5f642f3ba1384c3d3a02edd3d48c657c269609cc3fc",
                    "4b3a6ea660aac1e87dae5a252ab5588b5292d713f8c146f1a92d7b72f64bc91663c46e2beb33832e92ec0dccdf033f87",
                    "0x13e9ad59112fde3af4163eb5c2400b5e9a602576d5869ac1c569075f08c90ff6",
                    "0x708ac65ff2b0baaccc6dd954e2a93df46016bd04457636de06798fcc17f02be5");

    test_ecdsa_p256("0x74a4620c578601475fc169a9b84be613b4a16cb6acab8fd98848a6ec9fbd133d",
                    "0x42b9e35d347c107e63bd55f525f915bcf1e3d2b81d002d3c39acf10fc30645a1",
                    "a357e9fa283e8699373cb7c027e4c86084259f08662fd0fc064e7b2f6a33562fb2a9e938962eda99f43e5e2b012822b8",
                    "0x113a933ebc4d94ce1cef781e4829df0c493b0685d39fb2048ce01b21c398dbba",
                    "0x3005bd4ec63dbd04ce9ff0c6246ad65d27fcf62edb2b7e461589f9f0e7446ffd");

    test_ecdsa_p256("0x7e4078a1d50c669fb2996dd9bacb0c3ac7ede4f58fa0fa1222e78dbf5d1f4186",
                    "0x0014e46e90cc171fbb83ea34c6b78202ea8137a7d926f0169147ed5ae3d6596f",
                    "347d91b8295d9321c84ce2a5e1c5257c4ffaf0006d884ff7337d386c63f532db444a873b8047ba373bb3538b5664ab31",
                    "0xa26b9ad775ac37ff4c7f042cdc4872c5e4e5e800485f488ddfaaed379f468090",
                    "0xf88eae2019bebbba62b453b8ee3472ca5c67c267964cffe0cf2d2933c1723dff");

    test_ecdsa_p256("0xa62032dfdb87e25ed0c70cad20d927c7effeb2638e6c88ddd670f74df16090e5",
                    "0x44c5ee2cf740ded468f5d2efe13daa7c5234645a37c073af35330d03a4fed976",
                    "46252c7ed042d8b1f691a46b4f6ca5395106871bd413e277a3812beb1757d9fb056a9805aa31376fd60e0ac567265cdd",
                    "0xeb173b51fb0aec318950d097e7fda5c34e529519631c3e2c9b4550b903da417d",
                    "0xca2c13574bf1b7d56e9dc18315036a31b8bceddf3e2c2902dcb40f0cc9e31b45");

    test_ecdsa_p256("0x760b5624bd64d19c866e54ccd74ad7f98851afdbc3ddeae3ec2c52a135be9cfa",
                    "0xfeca15ce9350877102eee0f5af18b2fed89dc86b7df0bf7bc2963c1638e36fe8",
                    "1ec1470e867e27ab4800998382f623e27fc2a897a497e6a9cb7c3584b42080c65dbe1270dc479a454566653abd402f02",
                    "0xbdff14e4600309c2c77f79a25963a955b5b500a7b2d34cb172cd6acd52905c7b",
                    "0xb0479cdb3df79923ec36a104a129534c5d59f622be7d613aa04530ad2507d3a2");

    test_ecdsa_p256("0x6b738de3398b6ac57b9591f9d7985dd4f32137ad3460dcf8970c1390cb9eaf8d",
                    "0x83bc61e26d2bbbd3cf2d2ab445a2bc4ab5dde41f4a13078fd1d3cc36ab596d57",
                    "a59ca4dd2b0347f4f2702a8962878a206775fd91047040be60463119f02aa829b7360b940b2785395406c280375c5d90ee655e51d4120df256b9a6287161c7fc",
                    "0x275fa760878b4dc05e9d157fedfd8e9b1c9c861222a712748cb4b7754c043fb1",
                    "0x699d906bb8435a05345af3b37e3b357786939e94caae257852f0503adb1e0f7e");

    test_ecdsa_p256("0xf2a6674d4e86152a527199bed293fa63acde1b4d8a92b62e552210ba45c38792",
                    "0xc72565c24f0eee6a094af341ddd8579747b865f91c8ed5b44cda8a19cc93776f",
                    "9e359350e87e7573ad9894cd4aad6c6202a58e9938d098dbf65650fc6f04fce3664b9adb234bfa0821788223a306daaa3e62bd46b19d7eb7a725bc5bce8998f3",
                    "0x4782903d2aaf8b190dab5cae2223388d2d8bd845b3875d37485c54e1ded1d3d8",
                    "0xdfb40e406bfa074f0bf832771b2b9f186e2211f0bca279644a0ca8559acf39da");

    test_ecdsa_p256("0x70b877b5e365fcf08140b1eca119baba662879f38e059d074a2cb60b03ea5d39",
                    "0x5f56f94d591df40b9f3b8763ac4b3dbe622c956d5bd0c55658b6f46fa3deb201",
                    "ff5e80ccbb51b75742a1f0e632b4c6cd119692f2aca337378f7eb2f3b17fc3d912828b7e1655d2263d8757715eea31493aa89dfe1db143a8fa13f89a00379938",
                    "0x2ba2ea2d316f8937f184ad3028e364574d20a202e4e7513d7af57ac2456804d1",
                    "0x64fe94968d18c5967c799e0349041b9e40e6c6c92ebb475e80dd82f51cf07320");

    test_ecdsa_p256("0x3088d4f45d274cc5f418c8ecc4cbcf96be87491f420250f8cbc01cdf2503ec47",
                    "0x634db48198129237ed068c88ff5809f6211921a6258f548f4b64dd125921b78b",
                    "e9518ad1c62d686b9df1f5ae1f6797d8c5944a65fcf2244b763f47b9bc5db8ec360cbd17180e6d24678bc36a1535276733bab7817610399ef6257ca43361dfa0",
                    "0xacd9f3b63626c5f32103e90e1dd1695907b1904aa9b14f2132caef331321971b",
                    "0x15c04a8bd6c13ed5e9961814b2f406f064670153e4d5465dcef63c1d9dd52a87");

    test_ecdsa_p256("0x75a45758ced45ecf55f755cb56ca2601d794ebeaeb2e6107fe2fc443f580e23c",
                    "0x5303d47d5a75ec821d51a2ee7548448208c699eca0cd89810ffc1aa4faf81ead",
                    "9fd9a5f9b73f6d01894ceaf8a1e0327a0cac0dbc30153201bcccf09b6756e2f89198781e80a7ff5119cc2bb4402c731379f5ab5eda9264e3fe88b4b528e16598",
                    "0xebc85fc4176b446b3384ccc62fc2526b45665561a0e7e9404ac376c90e450b59",
                    "0x8b2c09428e62c5109d17ed0cf8f9fd7c370d018a2a73f701effc9b17d04852c6");

    test_ecdsa_p256("0x2177e20a2092a46667debdcc21e7e45d6da72f124adecbc5ada6a7bcc7b401d5",
                    "0x550e468f2626070a080afeeb98edd75a721eb773c8e62149f3e903cf9c4d7b61",
                    "bfc07b9a8a8941b99ac47d607356e5b68d7534fb3faccfbe97751397af359d31fe239179a1d856ffac49a9738e888f599123ee96ae202fb93b897e26bc83202e",
                    "0xf8250f073f34034c1cde58f69a85e2f5a030703ebdd4dbfb98d3b3690db7d114",
                    "0xa9e83e05f1d6e0fef782f186bedf43684c825ac480174d48b0e4d31505e27498");

    test_ecdsa_p256("0x7b9c592f61aae0555855d0b9ebb6fd00fb6746e8842e2523565c858630b9ba00",
                    "0xd35b2e168b1875bbc563bea5e8d63c4e38957c774a65e762959a349eaf263ba0",
                    "a051dcee66f456d9786785444cee2a3a342a8e27a5ebdf0e91553a0d257eea11af3a7df7e9310b46d95021a1880cd3f064c73447d92a31bacdb889f1e1390f49",
                    "0x66d057fd39958b0e4932bacd70a1769bbadcb62e4470937b45497a3d4500fabb",
                    "0x6c853b889e18b5a49ee54b54dd1aaedfdd642e30eba171c5cab677f0df9e7318");

    test_ecdsa_p256("0x82a1a96f4648393c5e42633ecdeb1d8245c78c5ea236b5bab460dedcc8924bc0",
                    "0xe8cbf03c34b5154f876de19f3bb6fd43cd2eabf6e7c95467bcfa8c8fc42d76fd",
                    "e1a00e6e38599d7eba1f1a8a6c7337e4dcbdd4f436f47c57d17ef85829f7e266b6bff67a001598db6b9ac032ad160d6f928f8724d2f10928cf953bc76c3fd2fb",
                    "0xcf7fc24bdaa09ac0cca8497e13298b961380668613c7493954048c06385a7044",
                    "0xf38b1c8306cf82ab76ee3a772b14416b49993fe11f986e9b0f0593c52ec91525");

    test_ecdsa_p256("0x42c292b0fbcc9f457ae361d940a9d45ad9427431a105a6e5cd90a345fe3507f7",
                    "0x313b08fd2fa351908b3178051ee782cc62b9954ad95d4119aa564900f8ade70c",
                    "bdcf1926e90c980373954c67d3c3c06ccb1a5076957673f12ddf23fa0cce7b3dc3ec2aec143a1ba58094e3da45e2b160092e1d943cf8f22fad35f8348575a0cf",
                    "0xf2bc35eb1b8488b9e8d4a1dbb200e1abcb855458e1557dc1bf988278a174eb3b",
                    "0xed9a2ec043a1d578e8eba6f57217976310e8674385ad2da08d6146c629de1cd9");

    test_ecdsa_p256("0x89dd22052ec3ab4840206a62f2270c21e7836d1a9109a3407dd0974c7802b9ae",
                    "0xe91609ba35c7008b080c77a9068d97a14ca77b97299e74945217672b2fd5faf0",
                    "da606bb1d0d25dd18a9c29096042e65e6b73086b30509962ea1aa75f25b74653c03a66620cba446f442765f28d7c55a5ff4f9693a6c7ce18e1196c25c12da48d",
                    "0xa70d1a2d555d599bfb8c9b1f0d43725341151d17a8d0845fa56f3563703528a7",
                    "0x4e05c45adf41783e394a5312f86e66871c4be4896948c85966879d5c66d54b37");

    test_ecdsa_p256("0xb0c0ad5e1f6001d8e9018ec611b2e3b91923e69fa6c98690ab644d650f640c42",
                    "0x610539c0b9ed21ac0a2f27527c1a61d9b47cbf033187b1a6ada006eb5b2662ed",
                    "efdb1d2143ecf0447a68e8156a7443897a56b31b4c0cfe499511a4a3ff6f32ba25515b3a20296a10d23378a24fb7de8c2ce606a7d93a9bd72aef3a34d1ff6401",
                    "0x83404dcf8320baf206381800071e6a75160342d19743b4f176960d669dd03d07",
                    "0x3f75dcf102008b2989f81683ae45e9f1d4b67a6ef6fd5c8af44828af80e1cfb5");

    test_ecdsa_p256("0x250f7112d381c1751860045d9bcaf20dbeb25a001431f96ac6f19109362ffebb",
                    "0x49fba9efe73546135a5a31ab3753e247034741ce839d3d94bd73936c4a17e4aa",
                    "eeb09b1f4a74744909774bfe707977e5234db27026873fc7b5496e37d363ff82d5a1dd6fa6c97717aa0828a6f6325a2b7970e5d836ddfb63bf47b09f136eb9da",
                    "0x7b195e92d2ba95911cda7570607e112d02a1c847ddaa33924734b51f5d81adab",
                    "0x10d9f206755cef70ab5143ac43f3f8d38aea2644f31d52eaf3b472ee816e11e5");

    test_ecdsa_p256("0x4ca87c5845fb04c2f76ae3273073b0523e356a445e4e95737260eba9e2d021db",
                    "0x0f86475d07f82655320fdf2cd8db23b21905b1b1f2f9c48e2df87e24119c4880",
                    "8cd8e7876555a7393128336880c8002136e1008814a691528111220fd14158b7ff822226c67390739db56b368cf69cecc4cc147220be3d3ce587c8ad75b0f55a",
                    "0x008c1755d3df81e64e25270dbaa9396641556df7ffc7ac9add6739c382705397",
                    "0x77df443c729b039aded5b516b1077fecdd9986402d2c4b01734ba91e055e87fc");

    test_ecdsa_p256("0x28afa3b0f81a0e95ad302f487a9b679fcdef8d3f40236ec4d4dbf4bb0cbba8b2",
                    "0xbb4ac1be8405cbae8a553fbc28e29e2e689fabe7def26d653a1dafc023f3cecf",
                    "7a951d7de2e3552d16912a1d4381f047577f9fd7a8f55dc8ebfb5eac9c859ab8771e222bf56d3330201b82751d0aa5b6c21f42ada05db9955d46f62d530723e1",
                    "0x15a9a5412d6a03edd71b84c121ce9a94cdd166e40da9ce4d79f1afff6a395a53",
                    "0x86bbc2b6c63bad706ec0b093578e3f064736ec69c0dba59b9e3e7f73762a4dc3");

    test_ecdsa_p256("0xc62cc4a39ace01006ad48cf49a3e71466955bbeeca5d318d672695df926b3aa4",
                    "0xc85ccf517bf2ebd9ad6a9e99254def0d74d1d2fd611e328b4a3988d4f045fe6f",
                    "4cb0debbdb572d89e2e46dcc6c2c63ef032792683032ce965b3e7fa79e3282039a705acbcc7bd07057a88b1e65852707934f10a67710ebefaa865201dfa6d4ff",
                    "0x6e7ff8ec7a5c48e0877224a9fa8481283de45fcbee23b4c252b0c622442c26ad",
                    "0x3dfac320b9c873318117da6bd856000a392b815659e5aa2a6a1852ccb2501df3");

}
