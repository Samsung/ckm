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
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <dpl/log/log.h>

#include <key-impl.h>
#include <certificate-impl.h>
#include <base64.h>

namespace CKM {

CertificateImpl::CertificateImpl(const RawBuffer &der, DataFormat format)
  : m_x509(NULL)
{
    int size;
    const unsigned char *ptr;
    RawBuffer tmp;

    LogDebug("Certificate to parse. Size: " << der.size());

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
        BIO_free_all(buff);
    } else {
        // TODO
        LogError("Unknown certificate format");
    }

    if (!m_x509) {
        // TODO
        LogError("Certificate could not be parsed.");
//        ThrowMsg(Exception::OpensslInternalError,
//          "Internal Openssl error in d2i_X509 function.");
    }
}

CertificateImpl::CertificateImpl(X509 *x509, bool duplicate)
{
    if (duplicate)
        m_x509 = X509_dup(x509);
    else
        m_x509 = x509;
}

CertificateImpl::CertificateImpl(const CertificateImpl &second){
    m_x509 = X509_dup(second.m_x509);
}

CertificateImpl::CertificateImpl(CertificateImpl &&second) {
    m_x509 = second.m_x509;
    second.m_x509 = NULL;
    LogDebug("Certificate moved: " << (void*)m_x509);
}

CertificateImpl& CertificateImpl::operator=(CertificateImpl &&second) {
    if (this == &second)
        return *this;
    X509_free(m_x509);
    m_x509 = second.m_x509;
    second.m_x509 = NULL;
    LogDebug("Certificate moved: " << (void*)m_x509);
    return *this;
}

CertificateImpl& CertificateImpl::operator=(const CertificateImpl &second) {
    if (this == &second)
        return *this;
    X509_free(m_x509);
    m_x509 = X509_dup(second.m_x509);
    return *this;
}

X509* CertificateImpl::getX509() const {
    return m_x509;
}

RawBuffer CertificateImpl::getDER(void) const {
    unsigned char *rawDer = NULL;
    int size = i2d_X509(m_x509, &rawDer);
    if (!rawDer || size <= 0) {
        LogError("i2d_X509 failed");
        return RawBuffer();
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

KeyImpl::EvpShPtr CertificateImpl::getEvpShPtr() const {
    return KeyImpl::EvpShPtr(X509_get_pubkey(m_x509), EVP_PKEY_free);
}

KeyImpl CertificateImpl::getKeyImpl() const {
    KeyImpl::EvpShPtr evp(X509_get_pubkey(m_x509), EVP_PKEY_free);
    switch(EVP_PKEY_type(evp->type))
    {
        case EVP_PKEY_RSA:
            return KeyImpl(evp, KeyType::KEY_RSA_PUBLIC);
        case EVP_PKEY_DSA:
            return KeyImpl(evp, KeyType::KEY_DSA_PUBLIC);
        case EVP_PKEY_EC:
            return KeyImpl(evp, KeyType::KEY_ECDSA_PUBLIC);
        default:
            LogError("Unsupported key type in certificate.");
            break;
    }
    return KeyImpl();
}

X509_NAME *getX509Name(X509 *x509, CertificateFieldId type) {
    if (!x509)
        return NULL;

    if (type == CertificateFieldId::ISSUER)
        return X509_get_issuer_name(x509);
    else if (type == CertificateFieldId::SUBJECT)
        return X509_get_subject_name(x509);

    LogError("Invalid param. Unknown CertificateFieldId");
    return NULL;
}

std::string CertificateImpl::getOneLine(CertificateFieldId type) const
{
    X509_NAME *name = getX509Name(m_x509, type);
    if (!name)
        return std::string();
    static const int MAXB = 1024;
    char buffer[MAXB];
    X509_NAME_oneline(name, buffer, MAXB);
    return std::string(buffer);
}

std::string CertificateImpl::getField(CertificateFieldId type, int fieldNid) const {
    X509_NAME *subjectName = getX509Name(m_x509, type);
    X509_NAME_ENTRY *subjectEntry = NULL;

    if (!subjectName)
        return std::string();

    int entryCount = X509_NAME_entry_count(subjectName);

    for (int i = 0; i < entryCount; ++i) {
        subjectEntry = X509_NAME_get_entry(subjectName, i);

        if (!subjectEntry) {
            continue;
        }

        int nid = OBJ_obj2nid(
            static_cast<ASN1_OBJECT*>(
                    X509_NAME_ENTRY_get_object(subjectEntry)));

        if (nid != fieldNid) {
            continue;
        }

        ASN1_STRING* pASN1Str = subjectEntry->value;

        unsigned char* pData = NULL;
        int nLength = ASN1_STRING_to_UTF8(&pData, pASN1Str);

        if (nLength < 0) {
            LogError("Reading field error.");
            return std::string();
        }

        std::string output(reinterpret_cast<char*>(pData), nLength);
        OPENSSL_free(pData);
        return output;
    }
    return std::string();
}

std::string CertificateImpl::getCommonName(CertificateFieldId type) const {
    return getField(type, NID_commonName);
}

std::string CertificateImpl::getCountryName(CertificateFieldId type) const {
    return getField(type, NID_countryName);
}

std::string CertificateImpl::getStateOrProvinceName(CertificateFieldId type) const {
    return getField(type, NID_stateOrProvinceName);
}

std::string CertificateImpl::getLocalityName(CertificateFieldId type) const {
    return getField(type, NID_localityName);
}

std::string CertificateImpl::getOrganizationName(CertificateFieldId type) const {
    return getField(type, NID_organizationName);
}

std::string CertificateImpl::getOrganizationalUnitName(CertificateFieldId type) const {
    return getField(type, NID_organizationalUnitName);
}

std::string CertificateImpl::getEmailAddres(CertificateFieldId type) const {
    return getField(type, NID_pkcs9_emailAddress);
}

std::string CertificateImpl::getOCSPURL() const {
    if (!m_x509)
        return std::string();

    STACK_OF(OPENSSL_STRING) *aia = X509_get1_ocsp(m_x509);

    if (NULL == aia)
        return std::string();

    std::string result(sk_OPENSSL_STRING_value(aia, 0));
    X509_email_free(aia);   // TODO is it correct?
    return result;
}

CertificateImpl::~CertificateImpl() {
    LogDebug("free cert start ptr: " << (void*)m_x509);
    X509_free(m_x509);
    LogDebug("free cert end");
}

CertificateShPtr Certificate::create(const RawBuffer &rawBuffer, DataFormat format) {
    try {
        CertificateShPtr output = std::make_shared<CertificateImpl>(rawBuffer, format);
        if (output->empty())
            output.reset();
        return output;
    } catch (const std::bad_alloc &) {
        LogDebug("Bad alloc was caught during CertificateImpl creation");
    } catch (...) {
        LogError("Critical error: Unknown exception was caught during CertificateImpl creation!");
    }
    return CertificateShPtr();
}

} // namespace CKM

