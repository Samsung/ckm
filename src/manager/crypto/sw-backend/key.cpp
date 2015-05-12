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
 * @file       key.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <memory>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <sw-backend/key.h>

#define EVP_SUCCESS 1	// DO NOTCHANGE THIS VALUE
#define EVP_FAIL    0	// DO NOTCHANGE THIS VALUE

namespace CKM {
namespace Crypto {
namespace SW {

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

RawBuffer AKey::sign(
    const CryptoAlgorithm &alg,
    const RawBuffer &message)
{
    (void) alg;
    (void) message;

    auto key = getEvpShPtr();
    return RawBuffer();
}

bool AKey::verify(const CryptoAlgorithm &alg, const RawBuffer &message, const RawBuffer &sign) {
    (void) alg;
    (void) message;
    (void) sign;

    auto key = getEvpShPtr();
    return false;
}

EvpShPtr AKey::getEvpShPtr() {
    if (m_evp)
        return m_evp;

    EVP_PKEY *pkey = NULL;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    LogDebug("Start to parse key:");

    if (!pkey) {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_key.data(), m_key.size());
        pkey = d2i_PrivateKey_bio(bio.get(), NULL);
        LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
    }

    if (!pkey) {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), m_key.data(), m_key.size());
        pkey = d2i_PUBKEY_bio(bio.get(), NULL);
        LogDebug("Trying d2i_PUBKEY_bio Status: " << (void*)pkey);
    }

    if (!pkey) {
        LogError("Failed to parse key");
        ThrowMsg(Exception::InternalError, "Failed to parse key");
    }

    m_evp.reset(pkey, EVP_PKEY_free);
    return m_evp;
}

} // namespace SW
} // namespace Crypto
} // namespace CKM

