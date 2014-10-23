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
 * @file        ckm-certificate.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Main header file for client library.
 */
#pragma once

#include <vector>
#include <memory>

#include <ckm/ckm-type.h>

extern "C" {
struct x509_st;
typedef struct x509_st X509;
}

// Central Key Manager namespace
namespace CKM {

class Certificate;
typedef std::shared_ptr<Certificate> CertificateShPtr;

class Certificate {
public:

    virtual bool empty() const = 0;

    // This function  will return openssl struct X509*.
    // You should not free the memory.
    // Memory will be freed in ~Certificate.
    virtual X509 *getX509() const = 0;
    virtual RawBuffer getDER() const = 0;
    virtual ~Certificate(){}

    static CertificateShPtr create(const RawBuffer &rawBuffer, DataFormat format);
};

typedef std::vector<CertificateShPtr> CertificateShPtrVector;

} // namespace CKM

