/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        certificate-stack.cpp
 * @author      Barlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Certificate Stack Implmentation.
 */
#include <openssl/x509.h>

#include <stdexcept>

#include <dpl/log/log.h>

#include <certificate-store.h>
#include <certificate-config.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>

namespace CKM {

namespace {
typedef std::unique_ptr<X509_STORE_CTX, void(*)(X509_STORE_CTX*)> X509_STORE_CTX_PTR;
typedef std::unique_ptr<STACK_OF(X509), void(*)(STACK_OF(X509)*)> X509_STACK_PTR;
}

CertificateStore::CertificateStore() : m_store(X509_STORE_new())
{
    if (!m_store) {
        LogError("Failed to create store");
        throw std::runtime_error("Failed to create store");
    }
}

CertificateStore::~CertificateStore()
{
    X509_STORE_free(m_store);
}

int CertificateStore::verifyCertificate(
    const CertificateImpl &cert,
    const CertificateImplVector &untrustedVector,
    const CertificateImplVector &trustedVector,
    bool useTrustedSystemCertificates,
    bool stateCCMode,
    CertificateImplVector &chainVector)
{
    int ret;
    LogDebug("Certificate for verfication ptr: " << (void*)cert.getX509());
    LogDebug("Verfication with " << untrustedVector.size() << " untrusted certificates" <<
             trustedVector.size() << "trusted certificates" << " and system certificates set to: "
             << useTrustedSystemCertificates);

    X509_STORE_CTX_PTR csc(X509_STORE_CTX_new(),X509_STORE_CTX_free);
    if (!csc) {
        LogError("failed to create csc");
        return CKM_API_ERROR_UNKNOWN;
    }

    if (useTrustedSystemCertificates) {
        ret = addSystemCertificateDirs();
        if (ret != CKM_API_SUCCESS)
            return ret;

        ret = addSystemCertificateFiles();
        if (ret != CKM_API_SUCCESS)
            return ret;
    }

    ret = addCustomTrustedCertificates(trustedVector);
    if (ret != CKM_API_SUCCESS)
        return ret;

    // create stack of untrusted certificates
    X509_STACK_PTR untrusted(sk_X509_new_null(), [](STACK_OF(X509)* stack) { sk_X509_free(stack); });
    if (!untrustedVector.empty()) {
        for (auto &e : untrustedVector) {
            // we don't want to free certificates because we wont create copies
            sk_X509_push(untrusted.get(), e.getX509());
        }
    }

    if (0 == X509_STORE_CTX_init(csc.get(), m_store, cert.getX509(), untrusted.get())) {
        LogError("failed to X509_STORE_CTX_init");
        return CKM_API_ERROR_UNKNOWN;
    }

    if(stateCCMode) {
        X509_VERIFY_PARAM_set_flags(csc->param, X509_V_FLAG_X509_STRICT);
    }

    int result = X509_verify_cert(csc.get()); // 1 == ok; 0 == fail; -1 == error

    LogDebug("Openssl verification result: " << result);

    if (result > 0) {
        STACK_OF(X509) *chain = X509_STORE_CTX_get_chain(csc.get());
        for (int i = 0; i < sk_X509_num(chain); ++i) {
            X509* icert = (X509*)sk_X509_value(chain, i);
            chainVector.push_back(CertificateImpl(icert));
        }
    }

    switch (result) {
    case 0:
        return CKM_API_ERROR_VERIFICATION_FAILED;
    case 1:
        return CKM_API_SUCCESS;
    default:
        return CKM_API_ERROR_UNKNOWN;
    }
}

int CertificateStore::addSystemCertificateDirs()
{
    const auto& dirs = CertificateConfig::getSystemCertificateDirs();
    if (dirs.empty())
        return CKM_API_SUCCESS;

    // add system certificate directories
    auto dir_lookup = X509_STORE_add_lookup(m_store, X509_LOOKUP_hash_dir());
    if (!dir_lookup) {
        LogError("Error in X509_STORE_add_lookup");
        return CKM_API_ERROR_UNKNOWN;
    }
    for(const auto& i: dirs) {
        if (!X509_LOOKUP_add_dir(dir_lookup, i.c_str(), X509_FILETYPE_PEM)) {
            LogError("Error in X509_LOOKUP_add_dir");
            return CKM_API_ERROR_UNKNOWN;
        }
    }
    return CKM_API_SUCCESS;
}

int CertificateStore::addSystemCertificateFiles()
{
    const auto& files = CertificateConfig::getSystemCertificateFiles();
    if (files.empty())
        return CKM_API_SUCCESS;

    // add system certificate files
    auto file_lookup = X509_STORE_add_lookup(m_store, X509_LOOKUP_file());
    if (!file_lookup) {
        LogError("Error in X509_STORE_add_lookup");
        return CKM_API_ERROR_UNKNOWN;
    }

    for(const auto& i:files) {
        if (!X509_LOOKUP_load_file(file_lookup, i.c_str(), X509_FILETYPE_PEM)) {
            LogError("Error in X509_LOOKUP_load_file");
            return CKM_API_ERROR_UNKNOWN;
        }
    }
    return CKM_API_SUCCESS;
}

int CertificateStore::addCustomTrustedCertificates(const CertificateImplVector &trustedVector)
{
    // add trusted certificates to store
    for (const auto& i:trustedVector) {
        if(1 != X509_STORE_add_cert(m_store, i.getX509())) {
            LogError("failed to add certificate to the store");
            return CKM_API_ERROR_UNKNOWN;
        }
    }
    return CKM_API_SUCCESS;
}

} // namespace CKM
