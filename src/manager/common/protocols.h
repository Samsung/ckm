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

#include <stdexcept>
#include <string>

#include <ckm/ckm-type.h>
#include <pkcs12-impl.h>

#include <dpl/exception.h>
#include <dpl/serialization.h>
#include <symbol-visibility.h>
#include <data-type.h>

namespace CKM {

COMMON_API extern char const * const SERVICE_SOCKET_ECHO;
COMMON_API extern char const * const SERVICE_SOCKET_CKM_CONTROL;
COMMON_API extern char const * const SERVICE_SOCKET_CKM_STORAGE;
COMMON_API extern char const * const SERVICE_SOCKET_OCSP;
COMMON_API extern char const * const SERVICE_SOCKET_ENCRYPTION;

enum class ControlCommand : int {
    UNLOCK_USER_KEY,
    LOCK_USER_KEY,
    REMOVE_USER_DATA,
    CHANGE_USER_PASSWORD,
    RESET_USER_PASSWORD,
    REMOVE_APP_DATA,
    UPDATE_CC_MODE,
    SET_PERMISSION
    // for backward compatibility append new at the end
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
    CREATE_KEY_PAIR_DSA,
    SET_PERMISSION,
    SAVE_PKCS12,
    GET_PKCS12
    // for backward compatibility append new at the end
};

enum class EncryptionCommand : int {
    ENCRYPT,
    DECRYPT
};

// (client side) Alias = (service side) Label::Name
COMMON_API extern char const * const LABEL_NAME_SEPARATOR;
COMMON_API extern char const * const LABEL_SYSTEM_DB;
typedef std::string Name;
typedef std::vector<std::pair<Label, Name> > LabelNameVector;

class IStream;

struct COMMON_API PolicySerializable : public Policy, ISerializable {
    PolicySerializable() {};
    explicit PolicySerializable(const Policy &policy) : Policy(policy) {}
    explicit PolicySerializable(IStream &stream) {
        Deserialization::Deserialize(stream, password);
        Deserialization::Deserialize(stream, extractable);
    }
    void Serialize(IStream &stream) const {
        Serialization::Serialize(stream, password);
        Serialization::Serialize(stream, extractable);
    }
};

struct COMMON_API PKCS12Serializable : public PKCS12Impl, ISerializable {
    PKCS12Serializable();
    explicit PKCS12Serializable(const PKCS12 &);
    explicit PKCS12Serializable(IStream &);
    PKCS12Serializable(
            const KeyShPtr &privKey,
            const CertificateShPtr &cert,
            const CertificateShPtrVector &chainCerts);
    void Serialize(IStream &) const;
};

struct COMMON_API CryptoAlgorithmSerializable : public CryptoAlgorithm, ISerializable {
    DECLARE_EXCEPTION_TYPE(Exception, Base);
    DECLARE_EXCEPTION_TYPE(Exception, UnsupportedParam);

    CryptoAlgorithmSerializable();
    explicit CryptoAlgorithmSerializable(const CryptoAlgorithm &);
    explicit CryptoAlgorithmSerializable(IStream &);

    void Serialize(IStream &) const;
};

} // namespace CKM

