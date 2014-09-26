/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by Central
 *              Key Manager.
 */
#pragma once

#include <ckm/ckm-type.h>

#include <dpl/serialization.h>

namespace CKM {

extern char const * const SERVICE_SOCKET_ECHO;
extern char const * const SERVICE_SOCKET_CKM_CONTROL;
extern char const * const SERVICE_SOCKET_CKM_STORAGE;
extern char const * const SERVICE_SOCKET_OCSP;

enum class ControlCommand : int {
    UNLOCK_USER_KEY,
    LOCK_USER_KEY,
    REMOVE_USER_DATA,
    CHANGE_USER_PASSWORD,
    RESET_USER_PASSWORD,
    REMOVE_APP_DATA,
    SET_CC_MODE
};

enum class LogicCommand : int {
    GET,
    GET_LIST,
    SAVE,
    REMOVE,
    CREATE_KEY_PAIR_RSA,
    CREATE_KEY_PAIR_ECDSA,
    GET_CHAIN_CERT,
    GET_CHAIN_ALIAS,
    CREATE_SIGNATURE,
    VERIFY_SIGNATURE,
    CREATE_KEY_PAIR_DSA
    // for backward compatibility append new on the end
};

// Do not use DB_KEY_FIRST and DB_KEY_LAST in the code.
// This values are only for db module!
enum class DBDataType : int {
    KEY_RSA_PUBLIC,
    DB_KEY_FIRST = KEY_RSA_PUBLIC,
    KEY_RSA_PRIVATE,
    KEY_ECDSA_PUBLIC,
    KEY_ECDSA_PRIVATE,
    KEY_DSA_PUBLIC,
    KEY_DSA_PRIVATE,
    KEY_AES,
    DB_KEY_LAST = KEY_AES,
    CERTIFICATE,
    BINARY_DATA,
};

DBDataType toDBDataType(KeyType key);
KeyType toKeyType(DBDataType dbDataType);

class IStream;

struct PolicySerializable : public Policy, ISerializable {
    PolicySerializable();
    explicit PolicySerializable(const Policy &);
    explicit PolicySerializable(IStream &);
    void Serialize(IStream &) const;
};

} // namespace CKM

