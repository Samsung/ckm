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
 * @file        pkcs12-impl.h
 * @author      Barlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Certificate Implmentation.
 */
#pragma once

#include <memory>

#include <ckm/ckm-pkcs12.h>

namespace CKM {

class PKCS12Impl : public PKCS12 {
public:
    PKCS12Impl(const RawBuffer &buffer, const Password &password);

    PKCS12Impl(const PKCS12Impl &) = delete;
    PKCS12Impl(PKCS12Impl &&) = delete;
    PKCS12Impl& operator=(const PKCS12Impl &) = delete;
    PKCS12Impl& operator=(PKCS12Impl &&) = delete;

    virtual KeyShPtr getKey() const;
    virtual CertificateShPtr getCertificate() const;
    virtual CertificateShPtrVector getCaCertificateShPtrVector() const;
    virtual bool empty() const;

    virtual ~PKCS12Impl();
protected:
    KeyShPtr m_pkey;
    CertificateShPtr m_cert;
    CertificateShPtrVector m_ca;
};

} // namespace CKM

