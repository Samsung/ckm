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
 * @file       key.h
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once
#include <memory>

#include <openssl/evp.h>

#include <generic-backend/gkey.h>

namespace CKM {
namespace Crypto {
namespace SW {

typedef std::unique_ptr<EVP_PKEY_CTX,std::function<void(EVP_PKEY_CTX*)>> ContextUPtr;
typedef std::shared_ptr<EVP_PKEY> EvpShPtr;

class SKey : public GKey {
public:
    SKey(RawBuffer buffer, KeyType keyType)
      : m_key(std::move(buffer))
      , m_type(keyType)
    {}
protected:
    RawBuffer m_key;
    KeyType m_type;
};

class AKey : public GKey {
public:
    AKey(RawBuffer buffer, KeyType keyType)
      : m_key(std::move(buffer))
      , m_type(keyType)
    {}
    virtual RawBuffer sign(const CryptoAlgorithm &alg, const RawBuffer &message);
    virtual bool verify(const CryptoAlgorithm &alg, const RawBuffer &message, const RawBuffer &sign);
    virtual ~AKey(){}
protected:
    virtual EvpShPtr getEvpShPtr();

    EvpShPtr m_evp;
    RawBuffer m_key;
    KeyType m_type;
};

} // namespace SW
} // namespace Crypto
} // namespace CKM

