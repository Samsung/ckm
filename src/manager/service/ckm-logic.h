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
 *
 * @file        ckm-logic.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#pragma once

#include <string>
#include <vector>

#include <message-buffer.h>
#include <protocols.h>
#include <ckm/ckm-type.h>
#include <connection-info.h>
#include <db-crypto.h>
#include <key-provider.h>
#include <crypto-logic.h>
#include <certificate-store.h>

namespace CKM {

struct UserData {
    KeyProvider    keyProvider;
    DBCrypto       database;
    CryptoLogic    crypto;
};

class CKMLogic {
public:
    CKMLogic();
    CKMLogic(const CKMLogic &) = delete;
    CKMLogic(CKMLogic &&) = delete;
    CKMLogic& operator=(const CKMLogic &) = delete;
    CKMLogic& operator=(CKMLogic &&) = delete;
    virtual ~CKMLogic();

    RawBuffer unlockUserKey(uid_t user, const Password &password);

    RawBuffer lockUserKey(uid_t user);

    RawBuffer removeUserData(uid_t user);

    RawBuffer changeUserPassword(
        uid_t user,
        const Password &oldPassword,
        const Password &newPassword);

    RawBuffer resetUserPassword(
        uid_t user,
        const Password &newPassword);

    RawBuffer removeApplicationData(const std::string &smackLabel);

    RawBuffer saveData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias,
        const RawBuffer &key,
        const PolicySerializable &policy);

    RawBuffer removeData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias);

    RawBuffer getData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias,
        const Password &password);

    RawBuffer getDataList(
        Credentials &cred,
        int commandId,
        DBDataType dataType);

    RawBuffer createKeyPair(
        Credentials &cred,
        LogicCommand protocol_cmd,
        int commandId,
        const int additional_param,
        const Alias &aliasPrivate,
        const Alias &alaisPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    RawBuffer getCertificateChain(
        Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const RawBufferVector &untrustedCertificates);

    RawBuffer getCertificateChain(
        Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const AliasVector &aliasVector);

    RawBuffer  createSignature(
        Credentials &cred,
        int commandId,
        const Alias &privateKeyAlias,
        const Password &password,           // password for private_key
        const RawBuffer &message,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

    RawBuffer verifySignature(
        Credentials &cred,
        int commandId,
        const Alias &publicKeyOrCertAlias,
        const Password &password,           // password for public_key (optional)
        const RawBuffer &message,
        const RawBuffer &signature,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

    RawBuffer setCCModeStatus(CCModeState mode_status);

private:

    int saveDataHelper(
        Credentials &cred,
        DBDataType dataType,
        const Alias &alias,
        const RawBuffer &key,
        const PolicySerializable &policy);

    int getDataHelper(
        Credentials &cred,
        DBDataType dataType,
        const Alias &alias,
        const Password &password,
        DBRow &row);

    int createKeyPairHelper(
        Credentials &cred,
        const KeyType key_type,
        const int additional_param,
        const Alias &aliasPrivate,
        const Alias &aliasPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    int getKeyHelper(
        Credentials &cred,
        const Alias &publicKeyOrCertAlias,
        const Password &password,           // password for public_key (optional)
        const KeyImpl &genericKey);

    std::map<uid_t, UserData> m_userDataMap;
    CertificateStore m_certStore;
    CCModeState cc_mode_status;
};

} // namespace CKM

