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

#include <dpl/log/log.h>

#include <certificate-store.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>

namespace CKM {

CertificateStore::CertificateStore()
  : m_store(X509_STORE_new())
{}

int CertificateStore::loadFile(const std::string &path) {
    if (!m_store) {
        LogError("CertificateStore is not initialized!");
        return CKM_API_ERROR_UNKNOWN;
    }

    auto lookup = X509_STORE_add_lookup(m_store, X509_LOOKUP_file());

    if (!lookup) {
        LogError("Error in X509_STORE_add_lookup");
        return CKM_API_ERROR_UNKNOWN;
    }

    if (!X509_LOOKUP_load_file(lookup, path.c_str(), X509_FILETYPE_PEM)) {
        LogError("Error in X509_LOOKUP_load_file");
        return CKM_API_ERROR_UNKNOWN;
    }
    return CKM_API_SUCCESS;
}

int CertificateStore::setSystemCertificateDir(const char *path) {
    if (!m_store) {
        LogError("CertificateStore is not initialized!");
        return CKM_API_ERROR_UNKNOWN;
    }

    auto lookup = X509_STORE_add_lookup(m_store, X509_LOOKUP_hash_dir());

    if (!lookup) {
        LogError("Error in X509_STORE_add_lookup");
        return CKM_API_ERROR_UNKNOWN;
    }

    if (!X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM)) {
        LogError("Error in X509_LOOKUP_add_dir");
        return CKM_API_ERROR_UNKNOWN;
    }
    return CKM_API_SUCCESS;
}

int CertificateStore::verifyCertificate(
    const CertificateImpl &cert,
    const CertificateImplVector &untrustedVector,
    CertificateImplVector &chainVector,
    bool stateCCMode)
{
    STACK_OF(X509) *untrusted = NULL;

    LogDebug("Verfication with " << chainVector.size() << " untrusted certificates");

    if (!untrustedVector.empty()) {
        untrusted = sk_X509_new_null();
        for (auto &e : untrustedVector) {
            sk_X509_push(untrusted, e.getX509());
        }
    }

    X509_STORE_CTX *csc = X509_STORE_CTX_new();
    if (!csc) {
        LogError("failed to create csc");
        return CKM_API_ERROR_UNKNOWN;
    }

    LogDebug("Certificate for verfication ptr: " << (void*)cert.getX509());

    if (0 == X509_STORE_CTX_init(csc, m_store, cert.getX509(), untrusted)) {
        LogError("failed to X509_STORE_CTX_init");
        return CKM_API_ERROR_UNKNOWN;
    }

    if(stateCCMode) {
        X509_VERIFY_PARAM_set_flags(csc->param, X509_V_FLAG_X509_STRICT);
    }

    int result = X509_verify_cert(csc); // 1 == ok; 0 == fail; -1 == error

    LogDebug("Openssl verification result: " << result);

    if (result > 0) {
        STACK_OF(X509) *chain = X509_STORE_CTX_get_chain(csc);
        for (int i = 0; i < sk_X509_num(chain); ++i) {
            X509* icert = (X509*)sk_X509_value(chain, i);
            chainVector.push_back(CertificateImpl(icert));
        }
    }

    X509_STORE_CTX_free(csc);
    if (untrusted) {
        // we don't want to free certificates because we did not create copies
        // sk_X509_pop_free(untrusted, X509_free);
        sk_X509_free(untrusted);
    }

    if (result == 1)
        return CKM_API_SUCCESS;
    if (result == 0)
        return CKM_API_ERROR_VERIFICATION_FAILED;
    return CKM_API_ERROR_UNKNOWN;
}

CertificateStore::~CertificateStore() {
    if (m_store)
        X509_STORE_free(m_store);
}

} // namespace CKM
