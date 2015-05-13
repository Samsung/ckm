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
 * @file       algo-param.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <ckm/ckm-type.h>
#include <cassert>

namespace CKM
{

bool CryptoAlgorithm::BufferParam::getBuffer(RawBuffer& buffer) const
{
    buffer = m_buffer;
    return true;
}

CryptoAlgorithm::BaseParamPtr CryptoAlgorithm::BufferParam::create(const RawBuffer& buffer)
{
    return BaseParamPtr(new CryptoAlgorithm::BufferParam(buffer));
}

bool CryptoAlgorithm::IntParam::getInt(uint64_t& value) const
{
    value = m_int;
    return true;
}

CryptoAlgorithm::BaseParamPtr CryptoAlgorithm::IntParam::create(uint64_t value)
{
    return BaseParamPtr(new CryptoAlgorithm::IntParam(value));
}

template <>
bool CryptoAlgorithm::getParam(ParamName name, RawBuffer& value) const
{
    auto param = m_params.find(name);
    if (param == m_params.end())
        return false;

    assert(param->second);
    return param->second->getBuffer(value);
}

template <>
bool CryptoAlgorithm::addParam(ParamName name, const RawBuffer& value)
{
    return m_params.emplace(name, BufferParam::create(value)).second;
}

} // namespace CKM
