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
 * @file        ckm-logic.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#include <dpl/serialization.h>
#include <dpl/log/log.h>

#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>
#include <key-provider.h>
#include <file-system.h>

#include <ckm-logic.h>
namespace CKM {

CKMLogic::CKMLogic(){
    int retCode = FileSystem::init();
    // TODO what can I do when init went wrong? exit(-1) ??
    if (retCode) {
        LogError("Fatal error in FileSystem::init()");
    }
}

CKMLogic::~CKMLogic(){}

RawBuffer CKMLogic::unlockUserKey(uid_t user, const std::string &password) {
    // TODO try catch for all errors that should be supported by error code
    int retCode = KEY_MANAGER_API_SUCCESS;

    UserData &handle = m_userDataMap[user];

    if (!(handle.keyProvider.isInitialized())) {
        auto &handle = m_userDataMap[user];

        FileSystem fs(user);
        auto wrappedDomainKEK = fs.getDomainKEK();

        if (wrappedDomainKEK.empty()) {
            wrappedDomainKEK = KeyProvider::generateDomainKEK(std::to_string(user), password);
            fs.saveDomainKEK(wrappedDomainKEK);
        }

        handle.keyProvider = KeyProvider(wrappedDomainKEK, password);
        handle.database = DBCrypto(fs.getDBPath(), handle.keyProvider.getDomainKEK());
    }

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::lockUserKey(uid_t user) {
    int retCode = KEY_MANAGER_API_SUCCESS;
    // TODO try catch for all errors that should be supported by error code
    m_userDataMap.erase(user);

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::removeUserData(uid_t user) {
    int retCode = KEY_MANAGER_API_SUCCESS;
    // TODO try catch for all errors that should be supported by error code
    m_userDataMap.erase(user);

    FileSystem fs(user);
    fs.removeUserData();

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::changeUserPassword(
    uid_t user,
    const std::string &oldPassword,
    const std::string &newPassword)
{
    int retCode = KEY_MANAGER_API_SUCCESS;
    // TODO try-catch
    FileSystem fs(user);
    auto wrappedDomainKEK = fs.getDomainKEK();
    if (wrappedDomainKEK.empty()) {
        retCode = KEY_MANAGER_API_ERROR_BAD_REQUEST;
    } else {
        wrappedDomainKEK = KeyProvider::reencrypt(wrappedDomainKEK, oldPassword, newPassword);
        fs.saveDomainKEK(wrappedDomainKEK);
    }
    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::resetUserPassword(
    uid_t user,
    const std::string &newPassword)
{
    int retCode = KEY_MANAGER_API_SUCCESS;
    // TODO try-catch
    if (0 == m_userDataMap.count(user)) {
        retCode = KEY_MANAGER_API_ERROR_BAD_REQUEST;
    } else {
        auto &handler = m_userDataMap[user];
        auto wrappedDomainKEK = handler.keyProvider.getDomainKEK(newPassword);
        FileSystem fs(user);
        fs.saveDomainKEK(wrappedDomainKEK);
    }

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::saveData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    int retCode = KEY_MANAGER_API_SUCCESS;

    if (0 == m_userDataMap.count(cred.uid)) {
        retCode = KEY_MANAGER_API_ERROR_DB_LOCKED;
    } else {
        RawBuffer iv(10,'c');

        DBRow row = {
            alias,
            cred.smackLabel,
            policy.restricted,
            policy.extractable,
            dataType,
            0,
            0,
            iv,
            key.size(),
            key };

        auto &handler = m_userDataMap[cred.uid];
        retCode = handler.database.saveDBRow(row);
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::SAVE));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, static_cast<int>(dataType));

    return response.Pop();
}

RawBuffer CKMLogic::removeData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias)
{
    (void)cred;
    (void)alias;

    int retCode = KEY_MANAGER_API_SUCCESS;

    if (0 == m_userDataMap.count(cred.uid)) {
        retCode = KEY_MANAGER_API_ERROR_DB_LOCKED;
    } else {
        // TODO
        auto &handler = m_userDataMap[cred.uid];
        (void)handler;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::REMOVE));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, static_cast<int>(dataType));

    return response.Pop();
}

RawBuffer CKMLogic::getData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias,
    const std::string &password)
{
    (void)dataType;
    (void)password;

    int retCode = KEY_MANAGER_API_SUCCESS;
    DBRow row;

    if (0 == m_userDataMap.count(cred.uid)) {
        retCode = KEY_MANAGER_API_ERROR_DB_LOCKED;
    } else {
        auto &handler = m_userDataMap[cred.uid];
        retCode = handler.database.getDBRow(alias, cred.smackLabel, row);
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, static_cast<int>(row.dataType));
    Serialization::Serialize(response, row.data);
    return response.Pop();
}

RawBuffer CKMLogic::getDataList(
    Credentials &cred,
    int commandId,
    DBDataType dataType)
{
    int retCode = KEY_MANAGER_API_SUCCESS;

    if (0 == m_userDataMap.count(cred.uid)) {
        retCode = KEY_MANAGER_API_ERROR_DB_LOCKED;
    } else {
        auto &handler = m_userDataMap[cred.uid];
        // TODO
        (void)handler;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET_LIST));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, static_cast<int>(dataType));
    Serialization::Serialize(response, AliasVector());
    return response.Pop();
}

RawBuffer CKMLogic::createKeyPairRSA(
    Credentials &cred,
    int commandId,
    int size,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    PolicySerializable policyPrivateKey,
    PolicySerializable policyPublicKey)
{ 
    (void)cred;
    (void)size;
    (void)privateKeyAlias;
    (void)publicKeyAlias,
    (void)policyPrivateKey;
    (void)policyPublicKey;
    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::CREATE_KEY_PAIR_RSA));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
 
    return response.Pop();
}

RawBuffer CKMLogic::createKeyPairECDSA(
    Credentials &cred,
    int commandId,
    int type,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    PolicySerializable policyPrivateKey,
    PolicySerializable policyPublicKey)
{
    (void)cred;
    (void)type;
    (void)privateKeyAlias;
    (void)publicKeyAlias,
    (void)policyPrivateKey;
    (void)policyPublicKey;
    
    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::CREATE_KEY_PAIR_RSA));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
 
    return response.Pop();
}

} // namespace CKM

