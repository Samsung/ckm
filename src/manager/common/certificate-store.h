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
 * @file        certificate-stack.h
 * @author      Barlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Certificate Stack Implmentation.
 */
#include <certificate-impl.h>
#include <symbol-visibility.h>

extern "C" {
struct x509_store_st;
typedef struct x509_store_st X509_STORE;
}

namespace CKM {

class COMMON_API CertificateStore {
public:
    CertificateStore();
    CertificateStore(const CertificateStore &) = delete;
    CertificateStore(CertificateStore &&) = delete;
    CertificateStore& operator=(CertificateStore &&) = delete;
    CertificateStore& operator=(const CertificateStore &) = delete;
    virtual ~CertificateStore();

    int verifyCertificate(
        const CertificateImpl &cert,
        const CertificateImplVector &untrustedVector,
        const CertificateImplVector &trustedVector,
        bool useTrustedSystemCertificates,
        bool stateCCMode,
        CertificateImplVector &chainVector);

private:
    int addSystemCertificateDirs();
    int addSystemCertificateFiles();
    int addCustomTrustedCertificates(const CertificateImplVector &trustedVector);

    X509_STORE* m_store;
};

} // namespace CKM

