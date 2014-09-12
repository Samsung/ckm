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
#include <CryptoService.h>
#include <ckm-logic.h>
#include <generic-key.h>

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

    try {
        if (0 == m_userDataMap.count(user) || !(m_userDataMap[user].keyProvider.isInitialized())) {
            auto &handle = m_userDataMap[user];
            FileSystem fs(user);
            auto wrappedDomainKEK = fs.getDomainKEK();

            if (wrappedDomainKEK.empty()) {
                wrappedDomainKEK = KeyProvider::generateDomainKEK(std::to_string(user), password);
                fs.saveDomainKEK(wrappedDomainKEK);
            }

            handle.keyProvider = KeyProvider(wrappedDomainKEK, password);

            RawBuffer key = handle.keyProvider.getPureDomainKEK();
            handle.database = DBCrypto(fs.getDBPath(), key);
            handle.crypto = DBCryptoModule(key);
            // TODO wipe key
        }
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("Error in KeyProvider " << e.GetMessage());
        retCode = KEY_MANAGER_API_ERROR_SERVER_ERROR;
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
        FileSystem fs(user);
        fs.saveDomainKEK(handler.keyProvider.getWrappedDomainKEK(newPassword));
    }

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

int CKMLogic::saveDataHelper(
    Credentials &cred,
    DBDataType dataType,
    const Alias &alias,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    if (0 == m_userDataMap.count(cred.uid))
        return KEY_MANAGER_API_ERROR_DB_LOCKED;

    DBRow row = { alias, cred.smackLabel, policy.restricted,
         policy.extractable, dataType, DBCMAlgType::NONE,
         0, RawBuffer(10, 'c'), key.size(), key };

    auto &handler = m_userDataMap[cred.uid];
    if (!handler.crypto.haveKey(cred.smackLabel)) {
        RawBuffer key;
        auto key_optional = handler.database.getKey(cred.smackLabel);
        if(!key_optional) {
            LogDebug("No Key in database found. Generating new one for label: "
                    << cred.smackLabel);
            key = handler.keyProvider.generateDEK(cred.smackLabel);
        } else {
            key = *key_optional;
        }

        key = handler.keyProvider.getPureDEK(key);
        handler.crypto.pushKey(cred.smackLabel, key);
        handler.database.saveKey(cred.smackLabel, key);
    }
    handler.crypto.encryptRow(policy.password, row);
    handler.database.saveDBRow(row);
    return KEY_MANAGER_API_SUCCESS;
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
    try {
        retCode = saveDataHelper(cred, dataType, alias, key, policy);
        LogDebug("SaveDataHelper returned: " << retCode);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = KEY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const DBCryptoModule::Exception::Base &e) {
        LogError("DBCryptoModule failed with message: " << e.GetMessage());
        retCode = KEY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::InternalError &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = KEY_MANAGER_API_ERROR_DB_ERROR;
    } catch (const DBCrypto::Exception::AliasExists &e) {
        LogError("DBCrypto couldn't save duplicate alias");
        retCode = KEY_MANAGER_API_ERROR_DB_ALIAS_EXISTS;
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
    int retCode = KEY_MANAGER_API_SUCCESS;

    if (0 < m_userDataMap.count(cred.uid)) {
        Try {
            m_userDataMap[cred.uid].database.deleteDBRow(alias, cred.smackLabel);
        } Catch (CKM::Exception) {
            LogError("Error in deleting row!");
            retCode = KEY_MANAGER_API_ERROR_DB_ERROR;
        }
    } else {
        retCode = KEY_MANAGER_API_ERROR_DB_LOCKED;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::REMOVE));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, static_cast<int>(dataType));

    return response.Pop();
}

int CKMLogic::getDataHelper(
    Credentials &cred,
    DBDataType dataType,
    const Alias &alias,
    const std::string &password,
    DBRow &row)
{

    if (0 == m_userDataMap.count(cred.uid))
        return KEY_MANAGER_API_ERROR_DB_LOCKED;

    auto &handler = m_userDataMap[cred.uid];

    DBCrypto::DBRowOptional row_optional;
    if (dataType == DBDataType::CERTIFICATE || dataType == DBDataType::BINARY_DATA) {
        row_optional = handler.database.getDBRow(alias, cred.smackLabel, dataType);
    } else if ((static_cast<int>(dataType) >= static_cast<int>(DBDataType::DB_KEY_FIRST))
            && (static_cast<int>(dataType) <= static_cast<int>(DBDataType::DB_KEY_LAST)))
    {
        row_optional = handler.database.getKeyDBRow(alias, cred.smackLabel);
    } else {
        LogError("Unknown type of requested data" << (int)dataType);
        return KEY_MANAGER_API_ERROR_BAD_REQUEST;
    }
    if(!row_optional) {
        LogError("No row for given alias, label and type");
        return KEY_MANAGER_API_ERROR_DB_ALIAS_UNKNOWN;
    } else {
        row = *row_optional;
    }

    if (!handler.crypto.haveKey(row.smackLabel)) {
        RawBuffer key;
        auto key_optional = handler.database.getKey(row.smackLabel);
        if(!key_optional) {
            LogError("No key for given label in database");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        key = *key_optional;
        key = handler.keyProvider.getPureDEK(key);
        handler.crypto.pushKey(cred.smackLabel, key);
    }
    handler.crypto.decryptRow(password, row);

    LogError("Datatype: " << (int) row.dataType);

    return KEY_MANAGER_API_SUCCESS;
}

RawBuffer CKMLogic::getData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias,
    const std::string &password)
{
    int retCode = KEY_MANAGER_API_SUCCESS;
    DBRow row;

    try {
        retCode = getDataHelper(cred, dataType, alias, password, row);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with error: " << e.GetMessage());
        retCode = KEY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const DBCryptoModule::Exception::Base &e) {
        LogError("DBCryptoModule failed with message: " << e.GetMessage());
        retCode = KEY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = KEY_MANAGER_API_ERROR_DB_ERROR;
    }

    if (KEY_MANAGER_API_SUCCESS != retCode) {
        row.data.clear();
        row.dataType = dataType;
    }

    LogError("Sending dataType: " << (int)row.dataType);

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
    AliasVector aliasVector;

    if (0 < m_userDataMap.count(cred.uid)) {
        auto &handler = m_userDataMap[cred.uid];
        Try {
            if (dataType == DBDataType::CERTIFICATE || dataType == DBDataType::BINARY_DATA) {
                handler.database.getAliases(dataType, cred.smackLabel, aliasVector);
            } else {
                handler.database.getKeyAliases(cred.smackLabel, aliasVector);
            }
        } Catch (CKM::Exception) {
            LogError("Failed to get aliases");
            retCode = KEY_MANAGER_API_ERROR_DB_ERROR;
        }
    } else {
        retCode = KEY_MANAGER_API_ERROR_DB_LOCKED;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET_LIST));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, static_cast<int>(dataType));
    Serialization::Serialize(response, aliasVector);
    return response.Pop();
}

int CKMLogic::createKeyPairRSAHelper(
    Credentials &cred,
    int size,
    const Alias &aliasPrivate,
    const Alias &aliasPublic,
    const PolicySerializable &policyPrivate,
    const PolicySerializable &policyPublic)
{
    if (0 >= m_userDataMap.count(cred.uid))
        return KEY_MANAGER_API_ERROR_DB_LOCKED;

    auto &handler = m_userDataMap[cred.uid];
    GenericKey prv, pub;
    CryptoService cr;
    int retCode;

    if (CKM_CRYPTO_CREATEKEY_SUCCESS != (retCode = cr.createKeyPairRSA(size, prv, pub))) {
        LogError("CryptoService failed with code: " << retCode);
        return KEY_MANAGER_API_ERROR_SERVER_ERROR; // TODO error code
    }

    retCode = saveDataHelper(cred,
                            toDBDataType(prv.getType()),
                            aliasPrivate,
                            prv.getDER(),
                            policyPrivate);

    if (KEY_MANAGER_API_SUCCESS != retCode)
        return retCode;

    retCode = saveDataHelper(cred,
                            toDBDataType(pub.getType()),
                            aliasPublic,
                            pub.getDER(),
                            policyPublic);

    if (KEY_MANAGER_API_SUCCESS != retCode) {
        handler.database.deleteDBRow(aliasPrivate, cred.smackLabel);
    }

    return retCode;
}

RawBuffer CKMLogic::createKeyPairRSA(
    Credentials &cred,
    int commandId,
    int size,
    const Alias &aliasPrivate,
    const Alias &aliasPublic,
    const PolicySerializable &policyPrivate,
    const PolicySerializable &policyPublic)
{
    int retCode = createKeyPairRSAHelper(
                        cred,
                        size,
                        aliasPrivate,
                        aliasPublic,
                        policyPrivate,
                        policyPublic);

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::CREATE_KEY_PAIR_RSA));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
 
    return response.Pop();
}

int CKMLogic::createKeyPairECDSAHelper(
    Credentials &cred,
    int type,
    const Alias &aliasPrivate,
    const Alias &aliasPublic,
    const PolicySerializable &policyPrivate,
    const PolicySerializable &policyPublic)
{
    if (0 >= m_userDataMap.count(cred.uid))
        return KEY_MANAGER_API_ERROR_DB_LOCKED;

    auto &handler = m_userDataMap[cred.uid];
    GenericKey prv, pub;
    CryptoService cr;
    int retCode;

    if (CKM_CRYPTO_CREATEKEY_SUCCESS != (retCode = cr.createKeyPairECDSA(
              static_cast<ElipticCurve>(type), prv, pub)))
    {
        LogError("CryptoService failed with code: " << retCode);
        return KEY_MANAGER_API_ERROR_SERVER_ERROR; // TODO error code
    }

    retCode = saveDataHelper(cred,
                            toDBDataType(prv.getType()),
                            aliasPrivate,
                            prv.getDER(),
                            policyPrivate);

    if (KEY_MANAGER_API_SUCCESS != retCode)
        return retCode;

    retCode = saveDataHelper(cred,
                            toDBDataType(pub.getType()),
                            aliasPublic,
                            pub.getDER(),
                            policyPublic);

    if (KEY_MANAGER_API_SUCCESS != retCode) {
        handler.database.deleteDBRow(aliasPrivate, cred.smackLabel);
    }

    return retCode;
}

RawBuffer CKMLogic::createKeyPairECDSA(
    Credentials &cred,
    int commandId,
    int type,
    const Alias &aliasPrivate,
    const Alias &aliasPublic,
    const PolicySerializable &policyPrivate,
    const PolicySerializable &policyPublic)
{
    int retCode = createKeyPairECDSAHelper(
                        cred,
                        type,
                        aliasPrivate,
                        aliasPublic,
                        policyPrivate,
                        policyPublic);

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::CREATE_KEY_PAIR_RSA));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
 
    return response.Pop();
}

} // namespace CKM

