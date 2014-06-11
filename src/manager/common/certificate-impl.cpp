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
 * @file        client-certificate-impl.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Key implementation.
 */
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <dpl/log/log.h>

#include <certificate-impl.h>
#include <base64.h>

namespace CKM {

CertificateImpl::CertificateImpl(const RawBuffer &der, DataFormat format)
  : m_x509(NULL)
{
    int size;
    const unsigned char *ptr;
    RawBuffer tmp;

    if (DataFormat::FORM_DER_BASE64 == format) {
        Base64Decoder base64;
        base64.reset();
        base64.append(der);
        base64.finalize();
        tmp = base64.get();
        ptr = reinterpret_cast<const unsigned char*>(tmp.data());
        size = static_cast<int>(tmp.size());
        m_x509 = d2i_X509(NULL, &ptr, size);
    } else if (DataFormat::FORM_DER == format) {
        ptr = reinterpret_cast<const unsigned char*>(der.data());
        size = static_cast<int>(der.size());
        m_x509 = d2i_X509(NULL, &ptr, size);
    } else if (DataFormat::FORM_PEM == format) {
        BIO *buff = BIO_new(BIO_s_mem());
        BIO_write(buff, der.data(), der.size());
        m_x509 = PEM_read_bio_X509(buff, NULL, NULL, NULL);
    } else {
        // TODO
        LogError("Unknown certificate format");
    }

//    if (!m_x509) {
//        // TODO
//        LogError("Internal Openssl error in d2i_X509 function.");
//        ThrowMsg(Exception::OpensslInternalError,
//          "Internal Openssl error in d2i_X509 function.");
//    }
}

CertificateImpl& CertificateImpl::operator=(const CertificateImpl &second) {
   m_x509 = X509_dup(second.m_x509);
   return *this;
}

RawBuffer CertificateImpl::getDER(void) const {
    unsigned char *rawDer = NULL;
    int size = i2d_X509(m_x509, &rawDer);
    if (!rawDer || size <= 0) {
        // TODO
//        LogError("i2d_X509 failed");
//        ThrowMsg(Exception::OpensslInternalError,
//          "i2d_X509 failed");
    }

    RawBuffer output(
        reinterpret_cast<char*>(rawDer),
        reinterpret_cast<char*>(rawDer) + size);
    OPENSSL_free(rawDer);
    return output;
}

bool CertificateImpl::empty() const {
    return m_x509 == NULL;
}

CertificateImpl::~CertificateImpl() {
    X509_free(m_x509);
}

} // namespace CKM

