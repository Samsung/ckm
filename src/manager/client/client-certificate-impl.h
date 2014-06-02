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
#include <ckm/ckm-type.h>
#include <ckm/key-manager.h>

extern "C" {
struct x509_st;
typedef struct x509_st X509;
}

namespace CKM {

class CertificateImpl {
public:
    CertificateImpl(){}
    CertificateImpl(const RawData &data, Certificate::Format format);
    CertificateImpl& operator=(const CertificateImpl &) = delete;
    RawData getDER() const;
    bool empty() const;

    ~CertificateImpl();

protected:
    X509* m_x509;
};

} // namespace CKM

