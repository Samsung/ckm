/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file       test_serialization.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <string>

#include <boost/test/unit_test.hpp>
#include <test_common.h>

#include <ckm/ckm-raw-buffer.h>
#include <protocols.h>
#include <message-buffer.h>

using namespace CKM;

namespace {
std::string IV_STR("1234567890123456");
std::string AAD_STR("sdfdsgsghrtkghwiuho3irhfoewituhre");
RawBuffer IV(IV_STR.begin(), IV_STR.end());
RawBuffer AAD(AAD_STR.begin(), AAD_STR.end());

void checkIntParam(const CryptoAlgorithm& algo, ParamName name, uint64_t expected)
{
    uint64_t integer;
    BOOST_REQUIRE_MESSAGE(algo.getParam(name, integer),
                          "Failed to get parameter " << static_cast<int>(name));
    BOOST_REQUIRE_MESSAGE(
            integer == expected,
            "Parameter " << static_cast<int>(name) <<
            " expected value: " << expected <<
            " got: " << integer);
}

void checkIntParamNegative(const CryptoAlgorithm& algo, ParamName name)
{
    uint64_t integer;
    BOOST_REQUIRE_MESSAGE(!algo.getParam(name, integer),
                          "Getting int parameter " << static_cast<int>(name) << " should fail");
}

void checkBufferParam(const CryptoAlgorithm& algo, ParamName name, RawBuffer expected)
{
    RawBuffer buffer;
    BOOST_REQUIRE_MESSAGE(algo.getParam(name, buffer),
                          "Failed to get buffer parameter " << static_cast<int>(name));
    BOOST_REQUIRE_MESSAGE(buffer == expected,
                          "Parameter " << static_cast<int>(name) << " different than expected");
}

void checkBufferParamNegative(const CryptoAlgorithm& algo, ParamName name)
{
    RawBuffer buffer;
    BOOST_REQUIRE_MESSAGE(!algo.getParam(name, buffer),
                          "Getting buffer parameter " << static_cast<int>(name) << " should fail");
}

template <typename T>
void addParam(CryptoAlgorithm& algo, ParamName name, const T& value, bool success)
{
    BOOST_REQUIRE_MESSAGE(success == algo.addParam(name, value),
                          "Adding param " << static_cast<int>(name) <<
                          " should " << (success ? "succeed":"fail"));
}

} // namespace anonymous

BOOST_AUTO_TEST_SUITE(SERIALIZATION_TEST)

BOOST_AUTO_TEST_CASE(Serialization_CryptoAlgorithm) {
    CryptoAlgorithm ca;
    addParam(ca,ParamName::ALGO_TYPE, static_cast<uint64_t>(AlgoType::AES_GCM), true);
    addParam(ca,ParamName::ED_IV, IV, true);
    addParam(ca,ParamName::ED_IV, AAD, false); // try to overwrite
    addParam(ca,ParamName::ED_TAG_LEN, 128, true);
    addParam(ca,ParamName::ED_AAD, AAD, true);

    CryptoAlgorithmSerializable input(ca);
    CryptoAlgorithmSerializable output;
    auto msg = MessageBuffer::Serialize(input);
    RawBuffer buffer = msg.Pop();
    MessageBuffer resp;
    resp.Push(buffer);
    resp.Deserialize(output);

    checkIntParam(output, ParamName::ALGO_TYPE, static_cast<uint64_t>(AlgoType::AES_GCM));
    checkBufferParam(output, ParamName::ED_IV, IV);
    checkIntParam(output, ParamName::ED_TAG_LEN, 128);
    checkBufferParam(output, ParamName::ED_AAD, AAD);

    // wrong type
    checkBufferParamNegative(output, ParamName::ALGO_TYPE);
    checkIntParamNegative(output, ParamName::ED_IV);

    // non-existing
    checkBufferParamNegative(output, ParamName::ED_CTR);
    checkIntParamNegative(output, ParamName::ED_CTR_LEN);
    checkBufferParamNegative(output, ParamName::ED_LABEL);
    checkIntParamNegative(output, ParamName::GEN_KEY_LEN);
    checkIntParamNegative(output, ParamName::GEN_EC);
    checkIntParamNegative(output, ParamName::SV_HASH_ALGO);
    checkIntParamNegative(output, ParamName::SV_RSA_PADDING);

    checkIntParamNegative(output, static_cast<ParamName>(666));
}

BOOST_AUTO_TEST_CASE(Serialization_CryptoAlgorithm_wrong_name) {
    CryptoAlgorithm ca;
    // unuspported param name
    addParam(ca, static_cast<ParamName>(666), 666, true);

    CryptoAlgorithmSerializable input(ca);
    CryptoAlgorithmSerializable output;
    auto msg = MessageBuffer::Serialize(input);
    RawBuffer buffer = msg.Pop();
    MessageBuffer resp;
    resp.Push(buffer);
    BOOST_REQUIRE_THROW(resp.Deserialize(output), CryptoAlgorithmSerializable::UnsupportedParam);
}

BOOST_AUTO_TEST_SUITE_END()
