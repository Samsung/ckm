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
 * @file       obj.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <memory>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <sw-backend/obj.h>
#include <sw-backend/internals.h>

#define EVP_SUCCESS 1    // DO NOTCHANGE THIS VALUE
#define EVP_FAIL    0    // DO NOTCHANGE THIS VALUE

namespace CKM {
namespace Crypto {
namespace SW {

namespace {

AlgoType key2algo(DataType type)
{
    switch (static_cast<int>(type)) {
    case DataType::Type::KEY_RSA_PRIVATE:
    case DataType::Type::KEY_RSA_PUBLIC:
        return AlgoType::RSA_SV;
    case DataType::Type::KEY_DSA_PRIVATE:
    case DataType::Type::KEY_DSA_PUBLIC:
        return AlgoType::DSA_SV;
    case DataType::Type::KEY_ECDSA_PRIVATE:
    case DataType::Type::KEY_ECDSA_PUBLIC:
        return AlgoType::ECDSA_SV;
    default:
        ThrowErr(Exc::Crypto::InputParam, "Invalid key type: ", type);
    }
}

} // namespace anonymous

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

RawBuffer SKey::encrypt(const CryptoAlgorithm &alg, const RawBuffer &data)
{
    return Internals::symmetricEncrypt(getBinary(), alg, data);
}
RawBuffer SKey::decrypt(const CryptoAlgorithm &alg, const RawBuffer &cipher)
{
    return Internals::symmetricDecrypt(getBinary(), alg, cipher);
}

RawBuffer AKey::sign(
    const CryptoAlgorithm &alg,
    const RawBuffer &message)
{
    CryptoAlgorithm algWithType(alg);
    algWithType.setParam(ParamName::ALGO_TYPE, key2algo(m_type));
    return Internals::sign(getEvpShPtr().get(), algWithType, message);
}

int AKey::verify(const CryptoAlgorithm &alg, const RawBuffer &message, const RawBuffer &sign)
{
    CryptoAlgorithm algWithType(alg);
    EVP_PKEY* evp = getEvpShPtr().get();
    AlgoType type;

    // setup algorithm type basing on evp key type if it doesn't exist
    if (!algWithType.getParam(ParamName::ALGO_TYPE, type)) {
        int subType = EVP_PKEY_type(evp->type);
        switch (subType) {
        case EVP_PKEY_RSA:
            type = AlgoType::RSA_SV; break;
        case EVP_PKEY_DSA:
            type = AlgoType::DSA_SV; break;
        case EVP_PKEY_EC:
            type = AlgoType::ECDSA_SV; break;
        default:
            ThrowErr(Exc::Crypto::InputParam, "Invalid key type: ", subType);
        }
        algWithType.setParam(ParamName::ALGO_TYPE, type);
    }
    return Internals::verify(evp, algWithType, message, sign);
}

RawBuffer AKey::encrypt(const CryptoAlgorithm &alg, const RawBuffer &data)
{
    return Internals::asymmetricEncrypt(getEvpShPtr(), alg, data);
}

RawBuffer AKey::decrypt(const CryptoAlgorithm &alg, const RawBuffer &data)
{
    return Internals::asymmetricDecrypt(getEvpShPtr(), alg, data);
}

EvpShPtr AKey::getEvpShPtr()
{
    if (m_evp)
        return m_evp;

    EVP_PKEY *pkey = NULL;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    LogDebug("Start to parse key:");

    if (!pkey) {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_raw.data(), m_raw.size());
        pkey = d2i_PrivateKey_bio(bio.get(), NULL);
        LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
    }

    if (!pkey) {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_raw.data(), m_raw.size());
        pkey = d2i_PUBKEY_bio(bio.get(), NULL);
        LogDebug("Trying d2i_PUBKEY_bio Status: " << (void*)pkey);
    }

    if (!pkey)
        ThrowErr(Exc::Crypto::InternalError, "Failed to parse key");

    m_evp.reset(pkey, EVP_PKEY_free);
    return m_evp;
}

EvpShPtr Cert::getEvpShPtr()
{
    if (m_evp)
        return m_evp;

    int size = static_cast<int>(m_raw.size());
    const unsigned char *ptr = reinterpret_cast<const unsigned char *>(m_raw.data());

    X509 *x509 = d2i_X509(NULL, &ptr, size);

    if (!x509)
        ThrowErr(Exc::Crypto::InternalError, "Failed to parse certificate.");

    m_evp.reset(X509_get_pubkey(x509), EVP_PKEY_free);
    X509_free(x509);
    return m_evp;
}

} // namespace SW
} // namespace Crypto
} // namespace CKM
