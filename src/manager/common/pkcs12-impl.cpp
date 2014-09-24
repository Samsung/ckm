/* Copyright (c) 2014 Samsung Electronics Co.
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
 * @file        pkcs12-impl.cpp
 * @author      Barlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Certificate Implmentation.
 */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <dpl/log/log.h>

#include <pkcs12-impl.h>

#include <certificate-impl.h>
#include <key-impl.h>

namespace CKM {
namespace {

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

} // anonymous namespace

PKCS12Impl::PKCS12Impl(const RawBuffer &buffer, const Password &password)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    ::PKCS12 *pkcs12 = NULL;

    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    LogDebug("Start to parse PKCS12");

    int result = BIO_write(bio.get(), buffer.data(), buffer.size());
    if (result != static_cast<int>(buffer.size())) {
        LogError("BIO_write failed. result = " << result << " Expected: " << buffer.size());
        return;
    }

    pkcs12 = d2i_PKCS12_bio(bio.get(), NULL);

    if (pkcs12 == NULL) {
        LogDebug("d2i_PKCS12_bio failed.");
        return;
    }

    if (!PKCS12_verify_mac(pkcs12, password.c_str(), password.size())) {
        LogDebug("Pkcs12 verify failed. Wrong password");
        return;
    }

    if (!PKCS12_parse(pkcs12, password.c_str(), &pkey, &cert, &ca)) {
        LogError("PKCS12_parse failed");
        return;
    }

    if (pkey) {
        KeyImpl::EvpShPtr ptr(pkey, EVP_PKEY_free);
        switch(EVP_PKEY_type(pkey->type))
        {
            case EVP_PKEY_RSA:
                m_pkey = std::make_shared<KeyImpl>(ptr, KeyType::KEY_RSA_PRIVATE);
                break;

            case EVP_PKEY_DSA:
                m_pkey = std::make_shared<KeyImpl>(ptr, KeyType::KEY_DSA_PRIVATE);
                break;

            case EVP_PKEY_EC:
                m_pkey = std::make_shared<KeyImpl>(ptr, KeyType::KEY_ECDSA_PRIVATE);
                break;

            default:
                LogError("Unsupported private key type.");
                EVP_PKEY_free(pkey);
                break;
        }
    }

    if (cert) {
        m_cert = std::make_shared<CertificateImpl>(cert, false);
    }

    if (ca) {
        while (sk_X509_num(ca) > 0) {
            X509 *top = sk_X509_pop(ca);
            m_ca.push_back(std::make_shared<CertificateImpl>(top, false));
        }

        sk_X509_pop_free(ca, X509_free);
    }
}

KeyShPtr PKCS12Impl::getKey() const {
    return m_pkey;
}

CertificateShPtr PKCS12Impl::getCertificate() const {
    return m_cert;
}

CertificateShPtrVector PKCS12Impl::getCaCertificateShPtrVector() const {
    return m_ca;
}

bool PKCS12Impl::empty() const {
    return m_pkey.get() == NULL && m_cert.get() == NULL && m_ca.empty();
}

PKCS12Impl::~PKCS12Impl()
{}

PKCS12ShPtr PKCS12::create(const RawBuffer &rawBuffer, const Password &password) {
    try {
        auto output = std::make_shared<PKCS12Impl>(rawBuffer, password);
        if (output->empty())
            output.reset();
        return output;
    } catch (const std::bad_alloc &e) {
        LogDebug("Bad alloc was caught during PKCS12 creation");
    } catch (...) {
        LogError("Critical error: Unknown exception was caught during PCKS12Impl creation!");
    }
    return PKCS12ShPtr();
}

} // namespace CKM

