/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 *
 * @file        ckm-type.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#pragma once

#include <stdint.h>
#include <cassert>

#include <string>
#include <vector>
#include <map>
#include <memory>

#include <ckm/ckm-raw-buffer.h>
#include <ckm/ckm-password.h>

#define KEY_MANAGER_API __attribute__((visibility("default")))

namespace CKM {

// used to pass password and raw key data
typedef std::vector<RawBuffer> RawBufferVector;
typedef std::string Alias;
typedef std::string Label;
typedef std::vector<Alias> AliasVector;

enum class KeyType : int {
    KEY_NONE = 0,
    KEY_RSA_PUBLIC,
    KEY_RSA_PRIVATE,
    KEY_ECDSA_PUBLIC,
    KEY_ECDSA_PRIVATE,
    KEY_DSA_PUBLIC,
    KEY_DSA_PRIVATE,
    KEY_AES
};

enum class DataFormat : int {
    FORM_DER_BASE64 = 0,
    FORM_DER,
    FORM_PEM
};

enum class ElipticCurve : int {
    prime192v1 = 0,
    prime256v1,
    secp384r1
};

enum class CertificateFieldId : int {
    ISSUER = 0,
    SUBJECT
};

struct Policy {
    Policy(const Password &pass = Password(), bool extract = true)
      : password(pass)
      , extractable(extract)
    {}
    virtual ~Policy(){}
    Password password;  // byte array used to encrypt data inside CKM
    bool extractable;   // if true key may be extracted from storage
};

enum class HashAlgorithm : int {
    NONE = 0,
    SHA1,
    SHA256,
    SHA384,
    SHA512
};

enum class RSAPaddingAlgorithm : int {
    NONE = 0,
    PKCS1,
    X931
};

enum class DBCMAlgType : int {
    NONE = 0,
    AES_GCM_256,
    COUNT
};

typedef int PermissionMask;
enum Permission: int {
    NONE            = 0x00,
    READ            = 0x01,
    REMOVE          = 0x02
    // keep in sync with ckmc_permission_e !
};

const char * ErrorToString(int error);

// algorithm parameters
enum class ParamName : int {
    ALGO_TYPE = 1,      // If there's no such param, the service will try to deduce the algorithm
                        // type from the key.

    // encryption & decryption
    ED_IV = 101,
    ED_CTR_LEN,
    ED_AAD,
    ED_TAG_LEN,
    ED_LABEL,

    // key generation
    GEN_KEY_LEN = 201,
    GEN_EC,             // elliptic curve (ElipticCurve)

    // sign & verify
    SV_HASH_ALGO = 301, // hash algorithm (HashAlgorithm)
    SV_RSA_PADDING,     // RSA padding (RSAPaddingAlgorithm)
};

// algorithm types (ALGO_TYPE param)
enum class AlgoType : int {
    AES_CTR = 1,
    AES_CBC,
    AES_GCM,
    AES_CFB,
    RSA_OAEP,
    RSA_SV,
    DSA_SV,
    ECDSA_SV,
    RSA_GEN,
    DSA_GEN,
    ECDSA_GEN,
};

// cryptographic algorithm description
class KEY_MANAGER_API CryptoAlgorithm {
public:
    template <typename T>
    bool getParam(ParamName name, T& value) const;

    // returns false if param 'name' already exists
    template <typename T>
    bool addParam(ParamName name, const T& value);

protected:
    class BaseParam {
    public:
        virtual bool getBuffer(RawBuffer&) const { return false; }
        virtual bool getInt(uint64_t&) const { return false; }
        virtual ~BaseParam() {}

    protected:
        BaseParam() {}
    };
    typedef std::shared_ptr<BaseParam> BaseParamPtr;

    class BufferParam : public BaseParam {
    public:
        bool getBuffer(RawBuffer& buffer) const;
        static BaseParamPtr create(const RawBuffer& buffer);
    private:
        explicit BufferParam(const RawBuffer& value) : m_buffer(value) {}

        RawBuffer m_buffer;
    };

    class IntParam : public BaseParam {
    public:
        static BaseParamPtr create(uint64_t value);
        bool getInt(uint64_t& value) const;
    private:
        explicit IntParam(uint64_t value) : m_int(value) {}

        uint64_t m_int;
    };

    std::map<ParamName, BaseParamPtr> m_params;
};

template <typename T>
bool CryptoAlgorithm::getParam(ParamName name, T& value) const {
    auto param = m_params.find(name);
    if (param == m_params.end())
        return false;

    assert(param->second);

    uint64_t valueTmp;
    if (param->second->getInt(valueTmp)) {
        value = static_cast<T>(valueTmp);
        return true;
    }
    return false;
}

template <>
bool CryptoAlgorithm::getParam(ParamName name, RawBuffer& value) const;

template <typename T>
bool CryptoAlgorithm::addParam(ParamName name, const T& value) {
    return m_params.emplace(name, IntParam::create(static_cast<uint64_t>(value))).second;
}

template <>
bool CryptoAlgorithm::addParam(ParamName name, const RawBuffer& value);

} // namespace CKM

