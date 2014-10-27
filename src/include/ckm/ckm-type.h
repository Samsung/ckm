/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckm-type.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#pragma once

#include <string>
#include <vector>

#include <ckm/ckm-raw-buffer.h>
#include <ckm/ckm-password.h>

namespace CKM {

// used to pass password and raw key data
typedef std::vector<RawBuffer> RawBufferVector;
typedef std::string Alias;
typedef std::vector<Alias> AliasVector;

enum class KeyType : int {
    KEY_NONE = 0,
    KEY_RSA_PUBLIC,
    KEY_RSA_PRIVATE,
    KEY_ECDSA_PUBLIC,
    KEY_ECDSA_PRIVATE,
    KEY_DSA_PUBLIC,
    KEY_DSA_PRIVATE,
    KEY_AES
};

enum class DataFormat : int {
    FORM_DER_BASE64 = 0,
    FORM_DER,
    FORM_PEM
};

enum class ElipticCurve : int {
    prime192v1 = 0,
    prime256v1,
    secp384r1
};

enum class CertificateFieldId : int {
    ISSUER = 0,
    SUBJECT
};

struct Policy {
    Policy(const Password &pass = Password(), bool extract = true)
      : password(pass)
      , extractable(extract)
    {}
    virtual ~Policy(){}
    Password password;  // byte array used to encrypt data inside CKM
    bool extractable;   // if true key may be extracted from storage
};

enum class HashAlgorithm : int {
    NONE = 0,
    SHA1,
    SHA256,
    SHA384,
    SHA512
};

enum class RSAPaddingAlgorithm : int {
    NONE = 0,
    PKCS1,
    X931
};

enum class DBCMAlgType : int {
    NONE = 0,
    AES_GCM_256,
    COUNT
};

enum class AccessRight: int {
    AR_READ = 0,
    AR_READ_REMOVE
};

const char * ErrorToString(int error);

} // namespace CKM

