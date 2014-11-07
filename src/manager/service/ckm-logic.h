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
#include <file-lock.h>
#include <access-control.h>

namespace CKM {

struct UserData {
    KeyProvider    keyProvider;
    DBCrypto       database;
    CryptoLogic    crypto;
};

class CKMLogic {
public:
    class Exception
    {
        public:
            DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
            DECLARE_EXCEPTION_TYPE(Base, InputDataInvalid);
    };

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

    RawBuffer removeApplicationData(
        const Label &smackLabel);

    RawBuffer saveData(
        const Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Name &name,
        const Label &label,
        const RawBuffer &key,
        const PolicySerializable &policy);

    RawBuffer removeData(
        const Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Name &name,
        const Label &label);

    RawBuffer getData(
        const Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Name &name,
        const Label &label,
        const Password &password);

    RawBuffer getDataList(
        const Credentials &cred,
        int commandId,
        DBDataType dataType);

    RawBuffer createKeyPair(
        const Credentials &cred,
        LogicCommand protocol_cmd,
        int commandId,
        const int additional_param,
        const Name &namePrivate,
        const Label &labelPrivate,
        const Name &namePublic,
        const Label &labelPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    RawBuffer getCertificateChain(
        const Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const RawBufferVector &untrustedCertificates);

    RawBuffer getCertificateChain(
        const Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const LabelNameVector &labelNameVector);

    RawBuffer  createSignature(
        const Credentials &cred,
        int commandId,
        const Name &privateKeyName,
        const Label & ownerLabel,
        const Password &password,           // password for private_key
        const RawBuffer &message,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

    RawBuffer verifySignature(
        const Credentials &cred,
        int commandId,
        const Name &publicKeyOrCertName,
        const Label &label,
        const Password &password,           // password for public_key (optional)
        const RawBuffer &message,
        const RawBuffer &signature,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding);

    RawBuffer updateCCMode();

    RawBuffer setPermission(
        const Credentials &cred,
        int command,
        int msgID,
        const Name &name,
        const Label &label,
        const Label &accessor_label,
        const Permission newPermission);

private:

    void verifyBinaryData(
        DBDataType dataType,
        const RawBuffer &input_data) const;

    int saveDataHelper(
        const Credentials &cred,
        DBDataType dataType,
        const Name &name,
        const Label &label,
        const RawBuffer &key,
        const PolicySerializable &policy);

    int removeDataHelper(
        const Credentials &cred,
        const Name &name,
        const Label &ownerLabel);

    int readDataRowHelper(
        const Name &name,
        const Label &ownerLabel,
        DBDataType dataType,
        DBCrypto & database,
        DBRow &row);

    int checkDataPermissionsHelper(
        const Name &name,
        const Label &ownerLabel,
        const Label &accessorLabel,
        const DBRow &row,
        bool exportFlag,
        DBCrypto & database);

    int readDataHelper(
        bool exportFlag,
        const Credentials &cred,
        DBDataType dataType,
        const Name &name,
        const Label &label,
        const Password &password,
        DBRow &row);

    int createKeyPairHelper(
        const Credentials &cred,
        const KeyType key_type,
        const int additional_param,
        const Name &namePrivate,
        const Label &labelPrivate,
        const Name &namePublic,
        const Label &labelPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    int getCertificateChainHelper(
        const Credentials &cred,
        const RawBuffer &certificate,
        const LabelNameVector &labelNameVector,
        RawBufferVector & chainRawVector);

    int setPermissionHelper(
        const Credentials &cred,
        const Name &name,
        const Label &ownerLabel,
        const Label &accessorLabel,
        const Permission newPermission);

    std::map<uid_t, UserData> m_userDataMap;
    CertificateStore m_certStore;
    AccessControl m_accessControl;
    //FileLock m_lock;
};

} // namespace CKM

