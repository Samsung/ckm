/*
 *  Copyright (c) 2014 Samsung Electronics Co.
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
 * @file        ckm-pkcs12.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Main header file for client library.
 */
#pragma once

#include <memory>

#include <ckm/ckm-certificate.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-key.h>
#include <ckm/ckm-type.h>

// Central Key Manager namespace
namespace CKM {

class PKCS12;
typedef std::shared_ptr<PKCS12> PKCS12ShPtr;

class KEY_MANAGER_API PKCS12 {
public:
    virtual KeyShPtr getKey() const = 0;

    virtual CertificateShPtr getCertificate() const = 0;

    virtual CertificateShPtrVector getCaCertificateShPtrVector() const = 0;

    virtual bool empty() const = 0;

    virtual ~PKCS12(){}

    static PKCS12ShPtr create(const RawBuffer &rawData, const Password &password = Password());
};

} // namespace CKM

