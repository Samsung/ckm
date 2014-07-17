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

    SafeBuffer unlockUserKey(uid_t user, const std::string &password);

    SafeBuffer lockUserKey(uid_t user);

    SafeBuffer removeUserData(uid_t user);

    SafeBuffer changeUserPassword(
        uid_t user,
        const std::string &oldPassword,
        const std::string &newPassword);

    SafeBuffer resetUserPassword(
        uid_t user,
        const std::string &newPassword);

    SafeBuffer saveData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias,
        const SafeBuffer &key,
        const PolicySerializable &policy);

    SafeBuffer removeData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias);

    SafeBuffer getData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias,
        const std::string &password);

    SafeBuffer getDataList(
        Credentials &cred,
        int commandId,
        DBDataType dataType);

    SafeBuffer createKeyPairRSA(
        Credentials &cred,
        int commandId,
        int size,
        const Alias &aliasPrivate,
        const Alias &alaisPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    SafeBuffer createKeyPairECDSA(
        Credentials &cred,
        int commandId,
        int type,
        const Alias &aliasPrivate,
        const Alias &aliasPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    SafeBuffer getCertificateChain(
        Credentials &cred,
        int commandId,
        const SafeBuffer &certificate,
        const SafeBufferVector &untrustedCertificates);

    SafeBuffer getCertificateChain(
        Credentials &cred,
        int commandId,
        const SafeBuffer &certificate,
        const AliasVector &aliasVector);

    SafeBuffer  createSignature(
        Credentials &cred,
        int commandId,
        const Alias &privateKeyAlias,
        const std::string &password,           // password for private_key
        const SafeBuffer &message,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

    SafeBuffer verifySignature(
        Credentials &cred,
        int commandId,
        const Alias &publicKeyOrCertAlias,
        const std::string &password,           // password for public_key (optional)
        const SafeBuffer &message,
        const SafeBuffer &signature,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

private:

    int saveDataHelper(
        Credentials &cred,
        DBDataType dataType,
        const Alias &alias,
        const SafeBuffer &key,
        const PolicySerializable &policy);

    int getDataHelper(
        Credentials &cred,
        DBDataType dataType,
        const Alias &alias,
        const std::string &password,
        DBRow &row);

    int createKeyPairRSAHelper(
        Credentials &cred,
        int size,
        const Alias &aliasPrivate,
        const Alias &aliasPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    int createKeyPairECDSAHelper(
        Credentials &cred,
        int type,
        const Alias &aliasPrivate,
        const Alias &aliasPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    int getKeyHelper(
        Credentials &cred,
        const Alias &publicKeyOrCertAlias,
        const std::string &password,           // password for public_key (optional)
        const GenericKey &genericKey);

    std::map<uid_t, UserData> m_userDataMap;
    CertificateStore m_certStore;
};

} // namespace CKM

