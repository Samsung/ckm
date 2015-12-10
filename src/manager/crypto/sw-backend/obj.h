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
 * @file       obj.h
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once
#include <memory>

#include <openssl/evp.h>

#include <generic-backend/gobj.h>
#include <data-type.h>

namespace CKM {
namespace Crypto {
namespace SW {

typedef std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> ContextUPtr;
typedef std::shared_ptr<EVP_PKEY> EvpShPtr;

class BData : public GObj {
public:
    BData(RawBuffer buffer, DataType keyType)
      : m_raw(std::move(buffer))
      , m_type(keyType)
    {
    }

    virtual RawBuffer getBinary() const { return m_raw; }
protected:
    RawBuffer m_raw;
    DataType m_type;
};

class SKey : public BData {
public:
    SKey(RawBuffer buffer, DataType keyType) : BData(std::move(buffer), keyType)
    {
    }

    virtual RawBuffer encrypt(const CryptoAlgorithm &, const RawBuffer &);
    virtual RawBuffer decrypt(const CryptoAlgorithm &, const RawBuffer &);
};

class AKey : public BData {
public:
    AKey(RawBuffer buffer, DataType dataType) : BData(std::move(buffer), dataType)
    {
    }
    virtual RawBuffer sign(const CryptoAlgorithm &alg, const RawBuffer &message);
    virtual int verify(const CryptoAlgorithm &alg, const RawBuffer &message, const RawBuffer &sign);
    virtual RawBuffer encrypt(const CryptoAlgorithm &, const RawBuffer &);
    virtual RawBuffer decrypt(const CryptoAlgorithm &, const RawBuffer &);
    virtual ~AKey() {}

protected:
    virtual EvpShPtr getEvpShPtr();

    EvpShPtr m_evp;
};

class Cert : public AKey {
public:
    Cert(RawBuffer buffer, DataType dataType)
      : AKey(std::move(buffer), dataType)
    {
    }
    virtual ~Cert() {}
protected:
    virtual EvpShPtr getEvpShPtr();
};

} // namespace SW
} // namespace Crypto
} // namespace CKM

