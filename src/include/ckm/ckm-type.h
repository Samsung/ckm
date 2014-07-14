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

namespace CKM {

// used to pass password and raw key data
typedef std::vector<unsigned char> RawBuffer;
typedef std::vector<RawBuffer> RawBufferVector;
typedef std::string Alias;
typedef std::vector<Alias> AliasVector;

enum class KeyType : int {
    KEY_NONE,
    KEY_RSA_PUBLIC,
    KEY_RSA_PRIVATE,
    KEY_ECDSA_PUBLIC,
    KEY_ECDSA_PRIVATE,
    KEY_AES
};

enum class DataFormat : int {
    FORM_DER_BASE64,
    FORM_DER,
    FORM_PEM
};

enum class ElipticCurve : int {
    prime192v1,
    prime256v1,
    secp384r1
};

enum class CertificateFieldId : int {
    ISSUER,
    SUBJECT
};

struct Policy {
    Policy(const std::string &pass = std::string(), bool extract = true, bool rest = false)
      : password(pass)
      , extractable(extract)
      , restricted(rest)
    {}
    virtual ~Policy(){}
    std::string password;  // byte array used to encrypt data inside CKM
    bool extractable;  // if true key may be extracted from storage
    bool restricted;   // if true only key owner may see data
};

// Added by Dongsun Lee
enum class HashAlgorithm : int {
    SHA1,
    SHA256,
    SHA384,
    SHA512
};

// Added by Dongsun Lee
enum class RSAPaddingAlgorithm : int {
    PKCS1,
//  SSLV23, // not supported
//  NONE, // not supported
//  PKCS1_OAEP, // not supported
    X931
};

enum class DBCMAlgType : int {
    NONE,
    AES_CBC_256,
    COUNT
};

// Internal types
class GenericKey;
class CertificateImpl;

const char * ErrorToString(int error);

} // namespace CKM

