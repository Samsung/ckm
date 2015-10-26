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
#include <file-lock.h>
#include <access-control.h>
#include <certificate-impl.h>
#include <sys/types.h>
#include <generic-backend/gobj.h>

#include <platform/decider.h>

namespace CKM {

struct UserData {
    KeyProvider    keyProvider;
    DB::Crypto     database;
    CryptoLogic    crypto;
};

class CKMLogic {
public:
    static const uid_t SYSTEM_DB_UID;

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
        const Name &name,
        const Label &label,
        const RawBuffer &data,
        DataType dataType,
        const PolicySerializable &policy);

    RawBuffer savePKCS12(
        const Credentials &cred,
        int commandId,
        const Name &name,
        const Label &label,
        const PKCS12Serializable &pkcs,
        const PolicySerializable &keyPolicy,
        const PolicySerializable &certPolicy);

    RawBuffer removeData(
        const Credentials &cred,
        int commandId,
        const Name &name,
        const Label &label);

    RawBuffer getData(
        const Credentials &cred,
        int commandId,
        DataType dataType,
        const Name &name,
        const Label &label,
        const Password &password);

    RawBuffer getPKCS12(
        const Credentials &cred,
        int commandId,
        const Name &name,
        const Label &label,
        const Password &keyPassword,
        const Password &certPassword);

    RawBuffer getDataList(
        const Credentials &cred,
        int commandId,
        DataType dataType);

    RawBuffer createKeyPair(
        const Credentials &cred,
        int commandId,
        const CryptoAlgorithmSerializable & keyGenParams,
        const Name &namePrivate,
        const Label &labelPrivate,
        const Name &namePublic,
        const Label &labelPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    RawBuffer createKeyAES(
        const Credentials &cred,
        int commandId,
        const int size,
        const Name &name,
        const Label &label,
        const PolicySerializable &policy);

    RawBuffer getCertificateChain(
        const Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const RawBufferVector &untrustedCertificates,
        const RawBufferVector &trustedCertificates,
        bool useTrustedSystemCertificates);

    RawBuffer getCertificateChain(
        const Credentials &cred,
        int commandId,
        const RawBuffer &certificate,
        const LabelNameVector &untrustedCertificates,
        const LabelNameVector &trustedCertificates,
        bool useTrustedSystemCertificates);

    RawBuffer  createSignature(
        const Credentials &cred,
        int commandId,
        const Name &privateKeyName,
        const Label & ownerLabel,
        const Password &password,           // password for private_key
        const RawBuffer &message,
        const CryptoAlgorithm &cryptoAlgorithm);

    RawBuffer verifySignature(
        const Credentials &cred,
        int commandId,
        const Name &publicKeyOrCertName,
        const Label &label,
        const Password &password,           // password for public_key (optional)
        const RawBuffer &message,
        const RawBuffer &signature,
        const CryptoAlgorithm &cryptoAlgorithm);

    RawBuffer updateCCMode();

    RawBuffer setPermission(
        const Credentials &cred,
        const int command,
        const int msgID,
        const Name &name,
        const Label &label,
        const Label &accessor_label,
        const PermissionMask permissionMask);

    int setPermissionHelper(
            const Credentials &cred,
            const Name &name,
            const Label &ownerLabel,
            const Label &accessorLabel,
            const PermissionMask permissionMask);

    int verifyAndSaveDataHelper(
        const Credentials &cred,
        const Name &name,
        const Label &label,
        const RawBuffer &data,
        DataType dataType,
        const PolicySerializable &policy);

    int getKeyForService(const Credentials &cred,
                         const Name &name,
                         const Label &label,
                         const Password& pass,
                         Crypto::GObjShPtr& key);

protected:
    int unlockSystemDB();

private:

    // select private/system database depending on asking uid and owner label.
    // output: database handler and effective label
    UserData & selectDatabase(const Credentials &incoming_cred,
                              const Label       &incoming_label);

    int unlockDatabase(uid_t            user,
                       const Password & password);

    void loadDKEKFile(
        uid_t user,
        const Password &password);

    void saveDKEKFile(
        uid_t user,
        const Password &password);

    int verifyBinaryData(
        DataType dataType,
        RawBuffer &input_data) const;

    int toBinaryData(
        DataType dataType,
        const RawBuffer &input_data,
        RawBuffer &output_data) const;

    int checkSaveConditions(
        const Credentials &cred,
        UserData &handler,
        const Name &name,
        const Label &label);

    int saveDataHelper(
        const Credentials &cred,
        const Name &name,
        const Label &label,
        DataType dataType,
        const RawBuffer &data,
        const PolicySerializable &policy);

    int saveDataHelper(
        const Credentials &cred,
        const Name &name,
        const Label &label,
        const PKCS12Serializable &pkcs,
        const PolicySerializable &keyPolicy,
        const PolicySerializable &certPolicy);

    DB::Row createEncryptedRow(
        CryptoLogic &crypto,
        const Name &name,
        const Label &label,
        DataType dataType,
        const RawBuffer &data,
        const Policy &policy) const;

    int getPKCS12Helper(
        const Credentials &cred,
        const Name &name,
        const Label &label,
        const Password &keyPassword,
        const Password &certPassword,
        KeyShPtr & privKey,
        CertificateShPtr & cert,
        CertificateShPtrVector & caChain);

    int extractPKCS12Data(
        CryptoLogic &crypto,
        const Name &name,
        const Label &ownerLabel,
        const PKCS12Serializable &pkcs,
        const PolicySerializable &keyPolicy,
        const PolicySerializable &certPolicy,
        DB::RowVector &output) const;

    int removeDataHelper(
        const Credentials &cred,
        const Name &name,
        const Label &ownerLabel);

    int readSingleRow(
        const Name &name,
        const Label &ownerLabel,
        DataType dataType,
        DB::Crypto & database,
        DB::Row &row);

    int readMultiRow(const Name &name,
        const Label &ownerLabel,
        DataType dataType,
        DB::Crypto & database,
        DB::RowVector &output);

    int checkDataPermissionsHelper(
        const Credentials &cred,
        const Name &name,
        const Label &ownerLabel,
        const Label &accessorLabel,
        const DB::Row &row,
        bool exportFlag,
        DB::Crypto & database);

    Crypto::GObjUPtr rowToObject(
        UserData& handler,
        DB::Row row,
        const Password& password);

    int readDataHelper(
        bool exportFlag,
        const Credentials &cred,
        DataType dataType,
        const Name &name,
        const Label &label,
        const Password &password,
        Crypto::GObjUPtr &obj);

    int readDataHelper(
        bool exportFlag,
        const Credentials &cred,
        DataType dataType,
        const Name &name,
        const Label &label,
        const Password &password,
        Crypto::GObjUPtr &obj,
        DataType& objDataType);

    int readDataHelper(
        bool exportFlag,
        const Credentials &cred,
        DataType dataType,
        const Name &name,
        const Label &label,
        const Password &password,
        Crypto::GObjUPtrVector &objs);

    int createKeyAESHelper(
        const Credentials &cred,
        const int size,
        const Name &name,
        const Label &label,
        const PolicySerializable &policy);

    int createKeyPairHelper(
        const Credentials &cred,
        const CryptoAlgorithmSerializable & keyGenParams,
        const Name &namePrivate,
        const Label &labelPrivate,
        const Name &namePublic,
        const Label &labelPublic,
        const PolicySerializable &policyPrivate,
        const PolicySerializable &policyPublic);

    int readCertificateHelper(
        const Credentials &cred,
        const LabelNameVector &labelNameVector,
        CertificateImplVector &certVector);

    int getCertificateChainHelper(
        const CertificateImpl &cert,
        const RawBufferVector &untrustedCertificates,
        const RawBufferVector &trustedCertificates,
        bool useTrustedSystemCertificates,
        RawBufferVector &chainRawVector);

    int getCertificateChainHelper(
        const Credentials &cred,
        const CertificateImpl &cert,
        const LabelNameVector &untrusted,
        const LabelNameVector &trusted,
        bool useTrustedSystemCertificates,
        RawBufferVector &chainRawVector);

    int getDataListHelper(
        const Credentials &cred,
        const DataType dataType,
        LabelNameVector &labelNameVector);

    int changeUserPasswordHelper(uid_t user,
                                 const Password &oldPassword,
                                 const Password &newPassword);

    int resetUserPasswordHelper(uid_t user, const Password &newPassword);

    int loadAppKey(UserData& handle, const Label& appLabel);

    AccessControl m_accessControl;
    Crypto::Decider m_decider;
    //FileLock m_lock;

protected:
    std::map<uid_t, UserData> m_userDataMap;
};

} // namespace CKM

