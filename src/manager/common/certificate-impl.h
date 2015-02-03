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
 * @file        client-certificate-impl.h
 * @author      Barlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Certificate Implmentation.
 */

#pragma once

#include <memory>
#include <vector>
#include <ckm/ckm-type.h>
#include <ckm/ckm-certificate.h>

#include <key-impl.h>
#include <symbol-visibility.h>

namespace CKM {

class COMMON_API CertificateImpl : public Certificate {
public:
    CertificateImpl() : m_x509(NULL) {}
    explicit CertificateImpl(X509* x509, bool duplicate = true);
    CertificateImpl(const RawBuffer &data, DataFormat format);
    CertificateImpl(const CertificateImpl &);
    CertificateImpl(CertificateImpl &&);
    CertificateImpl& operator=(const CertificateImpl &);
    CertificateImpl& operator=(CertificateImpl &&);

    virtual RawBuffer getDER() const;
    virtual bool empty() const;
    virtual X509* getX509() const;

    KeyImpl::EvpShPtr getEvpShPtr() const;
    KeyImpl getKeyImpl() const;

    std::string getOneLine(CertificateFieldId type) const;
    std::string getField(CertificateFieldId type, int fieldNid) const;
    std::string getCommonName(CertificateFieldId type) const;
    std::string getCountryName(CertificateFieldId type) const;
    std::string getStateOrProvinceName(CertificateFieldId type) const;
    std::string getLocalityName(CertificateFieldId type) const;
    std::string getOrganizationName(CertificateFieldId type) const;
    std::string getOrganizationalUnitName(CertificateFieldId type) const;
    std::string getEmailAddres(CertificateFieldId type) const;
    std::string getOCSPURL() const;

    virtual ~CertificateImpl();
protected:
    X509* m_x509;
};

typedef std::vector<CertificateImpl> CertificateImplVector;

} // namespace CKM

