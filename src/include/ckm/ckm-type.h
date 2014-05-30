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
typedef std::vector<unsigned char> RawData;
typedef std::string Alias;
typedef std::vector<Alias> AliasVector;

enum class KeyType : int {
    KEY_NONE,
    KEY_RSA_PUBLIC,
    KEY_RSA_PRIVATE,
    //        KEY_ECDSA_PUBLIC,
    //        KEY_ECDSA_PRIVATE,
    //        KEY_AES
};

struct Policy {
    Policy(const RawData &pass = RawData(), bool extract = true, bool rest = false)
      : password(pass)
      , extractable(extract)
      , restricted(rest)
    {}
    virtual ~Policy(){}
    RawData password;  // byte array used to encrypt data inside CKM
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
    XRSA_PKCS1_PADDING,
    XRSA_SSLV23_PADDING,
    XRSA_NO_PADDING,
    XRSA_PKCS1_OAEP_PADDING,
    XRSA_X931_PADDING
};

} // namespace CKM

