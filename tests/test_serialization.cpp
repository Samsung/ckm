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

struct BrokenParam : public BaseParam {
    static BaseParamPtr create() { return BaseParamPtr(new BrokenParam()); }
};

} // namespace anonymous

BOOST_AUTO_TEST_SUITE(SERIALIZATION_TEST)

BOOST_AUTO_TEST_CASE(Serialization_CryptoAlgorithm_positive) {
    CryptoAlgorithm ca;
    ca.m_type = AlgoType::AES_GCM;
    ca.m_params.emplace(ParamName::ED_IV, BufferParam::create(IV));
    ca.m_params.emplace(ParamName::ED_TAG_LEN, IntParam::create(128));
    ca.m_params.emplace(ParamName::ED_AAD, BufferParam::create(AAD));

    CryptoAlgorithmSerializable input(std::move(ca));
    CryptoAlgorithmSerializable output;
    auto msg = MessageBuffer::Serialize(input);
    RawBuffer buffer = msg.Pop();
    MessageBuffer resp;
    resp.Push(buffer);
    resp.Deserialize(output);

    BOOST_REQUIRE_MESSAGE(input.m_type == output.m_type,
                          "Algorithm types don't match: " << static_cast<int>(input.m_type) << "!="
                          << static_cast<int>(output.m_type));

    // compare params
    auto iit = input.m_params.cbegin();
    auto oit = output.m_params.cbegin();
    for(;iit != input.m_params.cend() && oit != output.m_params.cend(); iit++, oit++ )
    {
        BOOST_REQUIRE_MESSAGE(iit->first == oit->first,
                              "Param names do not match :" << static_cast<int>(iit->first) << "!="
                              << static_cast<int>(oit->first));
        uint64_t integer[2];
        RawBuffer buffer[2];
        if(CKM_API_SUCCESS == iit->second->getInt(integer[0]))
        {
            BOOST_REQUIRE_MESSAGE(CKM_API_SUCCESS == oit->second->getInt(integer[1]),
                                  "Param types do not match");
            BOOST_REQUIRE_MESSAGE(integer[0] == integer[1], "Integer params do not match");
        }
        else if(CKM_API_SUCCESS == iit->second->getBuffer(buffer[0]))
        {
            BOOST_REQUIRE_MESSAGE(CKM_API_SUCCESS == oit->second->getBuffer(buffer[1]),
                                  "Param types do not match");
            BOOST_REQUIRE_MESSAGE(buffer[0] == buffer[1], "Integer params do not match");
        }
        else
            BOOST_FAIL("Wrong param type");
    }
}

BOOST_AUTO_TEST_CASE(Serialization_CryptoAlgorithm_broken_param) {
    CryptoAlgorithm ca;
    ca.m_type = AlgoType::AES_GCM;
    // unuspported param type
    ca.m_params.emplace(ParamName::ED_IV, BrokenParam::create());

    CryptoAlgorithmSerializable input(std::move(ca));
    BOOST_REQUIRE_THROW(auto buffer = MessageBuffer::Serialize(input),
                        CryptoAlgorithmSerializable::UnsupportedParam);
}

BOOST_AUTO_TEST_CASE(Serialization_CryptoAlgorithm_wrong_name) {
    CryptoAlgorithm ca;
    ca.m_type = AlgoType::AES_GCM;
    // unuspported param name
    ca.m_params.emplace(static_cast<ParamName>(666), IntParam::create(666));

    CryptoAlgorithmSerializable input(std::move(ca));
    CryptoAlgorithmSerializable output;
    auto msg = MessageBuffer::Serialize(input);
    RawBuffer buffer = msg.Pop();
    MessageBuffer resp;
    resp.Push(buffer);
    BOOST_REQUIRE_THROW(resp.Deserialize(output), CryptoAlgorithmSerializable::UnsupportedParam);
}

BOOST_AUTO_TEST_SUITE_END()
