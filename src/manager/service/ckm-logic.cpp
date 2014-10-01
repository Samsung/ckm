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
#include <key-impl.h>

namespace {
const char * const CERT_SYSTEM_DIR = "/etc/ssl/certs";
} // anonymous namespace

namespace CKM {

CKMLogic::CKMLogic()
{
    int retCode = FileSystem::init();
    // TODO what can I do when init went wrong? exit(-1) ??
    if (retCode) {
        LogError("Fatal error in FileSystem::init()");
    }

    if (CKM_API_SUCCESS != m_certStore.setSystemCertificateDir(CERT_SYSTEM_DIR)) {
        LogError("Fatal error in CertificateStore::setSystemCertificateDir. Chain creation will not work");
    }

    cc_mode_status = CCModeState::CC_MODE_OFF;
}

CKMLogic::~CKMLogic(){}

RawBuffer CKMLogic::unlockUserKey(uid_t user, const Password &password) {
    // TODO try catch for all errors that should be supported by error code
    int retCode = CKM_API_SUCCESS;

    try {
        if (0 == m_userDataMap.count(user) || !(m_userDataMap[user].keyProvider.isInitialized())) {
            auto &handle = m_userDataMap[user];
            FileSystem fs(user);
            auto wrappedDomainKEK = fs.getDKEK();

            if (wrappedDomainKEK.empty()) {
                wrappedDomainKEK = KeyProvider::generateDomainKEK(std::to_string(user), password);
                fs.saveDKEK(wrappedDomainKEK);
            }

            handle.keyProvider = KeyProvider(wrappedDomainKEK, password);

            auto wrappedDatabaseDEK = fs.getDBDEK();

            if (wrappedDatabaseDEK.empty()) {
                wrappedDatabaseDEK = handle.keyProvider.generateDEK(std::to_string(user));
                fs.saveDBDEK(wrappedDatabaseDEK);
            }

            RawBuffer key = handle.keyProvider.getPureDEK(wrappedDatabaseDEK);
            handle.database = DBCrypto(fs.getDBPath(), key);
            handle.crypto = CryptoLogic();

            // remove data of removed apps during locked state
            AppLabelVector removedApps = fs.clearRemovedsApps();
            for(auto& appSmackLabel : removedApps) {
                handle.database.deleteKey(appSmackLabel);
            }

            // TODO wipe key
        }
    } catch (const KeyProvider::Exception::PassWordError &e) {
        LogError("Incorrect Password " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("Error in KeyProvider " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    if(retCode != CKM_API_SUCCESS) {
        // When not successful, UserData in m_userDataMap should be erased.
        // Because other operations make decision based on the existence of UserData in m_userDataMap.
        m_userDataMap.erase(user);
    }

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::setCCModeStatus(CCModeState mode_status) {

    int retCode = CKM_API_SUCCESS;

    if((mode_status != CCModeState:: CC_MODE_OFF) && (mode_status != CCModeState:: CC_MODE_ON)) {
        retCode = CKM_API_ERROR_INPUT_PARAM;
    }

    cc_mode_status = mode_status;

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::lockUserKey(uid_t user) {
    int retCode = CKM_API_SUCCESS;
    // TODO try catch for all errors that should be supported by error code
    m_userDataMap.erase(user);

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::removeUserData(uid_t user) {
    int retCode = CKM_API_SUCCESS;
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
    const Password &oldPassword,
    const Password &newPassword)
{
    int retCode = CKM_API_SUCCESS;
    try {
        FileSystem fs(user);
        auto wrappedDomainKEK = fs.getDKEK();
        if (wrappedDomainKEK.empty()) {
            retCode = CKM_API_ERROR_BAD_REQUEST;
        } else {
            wrappedDomainKEK = KeyProvider::reencrypt(wrappedDomainKEK, oldPassword, newPassword);
            fs.saveDKEK(wrappedDomainKEK);
        }
    } catch (const KeyProvider::Exception::PassWordError &e) {
        LogError("Incorrect Password " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("Error in KeyProvider " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::resetUserPassword(
    uid_t user,
    const Password &newPassword)
{
    int retCode = CKM_API_SUCCESS;
    // TODO try-catch
    if (0 == m_userDataMap.count(user)) {
        retCode = CKM_API_ERROR_BAD_REQUEST;
    } else {
        auto &handler = m_userDataMap[user];
        FileSystem fs(user);
        fs.saveDKEK(handler.keyProvider.getWrappedDomainKEK(newPassword));
    }

    MessageBuffer response;
    Serialization::Serialize(response, retCode);
    return response.Pop();
}

RawBuffer CKMLogic::removeApplicationData(const std::string &smackLabel) {
    int retCode = CKM_API_SUCCESS;

    try {

        if (smackLabel.empty()) {
            retCode = CKM_API_ERROR_INPUT_PARAM;
        } else {
            UidVector uids = FileSystem::getUIDsFromDBFile();
            for (auto userId : uids) {
                if (0 == m_userDataMap.count(userId)) {
                    FileSystem fs(userId);
                    fs.addRemovedApp(smackLabel);
                } else {
                    auto &handle = m_userDataMap[userId];
                    handle.database.deleteKey(smackLabel);
                }
            }
        }

    } catch (const DBCrypto::Exception::InternalError &e) {
        LogError("DBCrypto couldn't remove data: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const DBCrypto::Exception::TransactionError &e) {
        LogError("DBCrypto transaction failed with message " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
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
        return CKM_API_ERROR_DB_LOCKED;

    DBRow row = { alias, cred.smackLabel,
         policy.extractable, dataType, DBCMAlgType::NONE,
         0, RawBuffer(), static_cast<int>(key.size()), key, RawBuffer() };

    auto &handler = m_userDataMap[cred.uid];
    DBCrypto::Transaction transaction(&handler.database);
    if (!handler.crypto.haveKey(cred.smackLabel)) {
        RawBuffer key;
        auto key_optional = handler.database.getKey(cred.smackLabel);
        if(!key_optional) {
            LogDebug("No Key in database found. Generating new one for label: "
                    << cred.smackLabel);
            key = handler.keyProvider.generateDEK(cred.smackLabel);
            handler.database.saveKey(cred.smackLabel, key);
        } else {
            LogDebug("Key from DB");
            key = *key_optional;
        }

        key = handler.keyProvider.getPureDEK(key);
        handler.crypto.pushKey(cred.smackLabel, key);
    }

    // Do not encrypt data with password during cc_mode on
    if(cc_mode_status == CCModeState::CC_MODE_ON) {
        handler.crypto.encryptRow("", row);
    } else {
        handler.crypto.encryptRow(policy.password, row);
    }

    handler.database.saveDBRow(row);
    transaction.commit();
    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::saveData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    int retCode = CKM_API_SUCCESS;
    try {
        retCode = saveDataHelper(cred, dataType, alias, key, policy);
        LogDebug("SaveDataHelper returned: " << retCode);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::InternalError &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const DBCrypto::Exception::AliasExists &e) {
        LogError("DBCrypto couldn't save duplicate alias");
        retCode = CKM_API_ERROR_DB_ALIAS_EXISTS;
    } catch (const DBCrypto::Exception::TransactionError &e) {
        LogError("DBCrypto transaction failed with message " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
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
    int retCode = CKM_API_SUCCESS;

    if (0 < m_userDataMap.count(cred.uid)) {
        Try {
            auto erased = m_userDataMap[cred.uid].database.deleteDBRow(alias, cred.smackLabel);
            // check if the data existed or not
            if(!erased) {
                LogError("No row for given alias and label");
                retCode = CKM_API_ERROR_DB_ALIAS_UNKNOWN;
            }
        } Catch (DBCrypto::Exception::PermissionDenied) {
            LogError("Error: not enough permissions!");
            retCode = CKM_API_ERROR_ACCESS_DENIED;
        } Catch (CKM::Exception) {
            LogError("Error in deleting row!");
            retCode = CKM_API_ERROR_DB_ERROR;
        }
    } else {
        retCode = CKM_API_ERROR_DB_LOCKED;
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
    const Password &password,
    DBRow &row)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

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
        return CKM_API_ERROR_BAD_REQUEST;
    }
    if(!row_optional) {
        LogError("No row for given alias, label and type");
        return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
    } else {
        row = *row_optional;
    }

    if (!handler.crypto.haveKey(row.smackLabel)) {
        RawBuffer key;
        auto key_optional = handler.database.getKey(row.smackLabel);
        if(!key_optional) {
            LogError("No key for given label in database");
            return CKM_API_ERROR_DB_ERROR;
        }
        key = *key_optional;
        key = handler.keyProvider.getPureDEK(key);
        handler.crypto.pushKey(cred.smackLabel, key);
    }
    handler.crypto.decryptRow(password, row);

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::getData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias,
    const Password &password)
{
    int retCode = CKM_API_SUCCESS;
    DBRow row;

    try {
        retCode = getDataHelper(cred, dataType, alias, password, row);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::PermissionDenied &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_ACCESS_DENIED;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    if (CKM_API_SUCCESS != retCode) {
        row.data.clear();
        row.dataType = dataType;
    }

    if ((CKM_API_SUCCESS == retCode) && (row.exportable == 0)) {
        row.data.clear();
        retCode = CKM_API_ERROR_NOT_EXPORTABLE;
    }

    // Prevent extracting private keys during cc-mode on
    if((cc_mode_status == CCModeState::CC_MODE_ON) && (row.dataType == DBDataType::KEY_RSA_PRIVATE || row.dataType == DBDataType::KEY_ECDSA_PRIVATE ||  row.dataType == DBDataType::KEY_DSA_PRIVATE)) {
        row.data.clear();
        retCode = CKM_API_ERROR_BAD_REQUEST;
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
    int retCode = CKM_API_SUCCESS;
    AliasVector aliasVector;

    if (0 < m_userDataMap.count(cred.uid)) {
        auto &handler = m_userDataMap[cred.uid];
        Try {
            if (dataType == DBDataType::CERTIFICATE || dataType == DBDataType::BINARY_DATA) {
                handler.database.getAliases(cred.smackLabel, dataType, aliasVector);
            } else {
                handler.database.getKeyAliases(cred.smackLabel, aliasVector);
            }
        } Catch (CKM::Exception) {
            LogError("Failed to get aliases");
            retCode = CKM_API_ERROR_DB_ERROR;
        }
    } else {
        retCode = CKM_API_ERROR_DB_LOCKED;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET_LIST));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, static_cast<int>(dataType));
    Serialization::Serialize(response, aliasVector);
    return response.Pop();
}


int CKMLogic::createKeyPairHelper(
    Credentials &cred,
    const KeyType key_type,
    const int additional_param,
    const Alias &aliasPrivate,
    const Alias &aliasPublic,
    const PolicySerializable &policyPrivate,
    const PolicySerializable &policyPublic)
{
    if (0 >= m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    auto &handler = m_userDataMap[cred.uid];
    KeyImpl prv, pub;
    int retCode;
    switch(key_type)
    {
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_RSA_PRIVATE:
            retCode = CryptoService::createKeyPairRSA(additional_param, prv, pub);
            break;

        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_DSA_PRIVATE:
            retCode = CryptoService::createKeyPairDSA(additional_param, prv, pub);
            break;

        case KeyType::KEY_ECDSA_PUBLIC:
        case KeyType::KEY_ECDSA_PRIVATE:
            retCode = CryptoService::createKeyPairECDSA(static_cast<ElipticCurve>(additional_param), prv, pub);
            break;

        default:
            return CKM_API_ERROR_INPUT_PARAM;
    }

    if (CKM_CRYPTO_CREATEKEY_SUCCESS != retCode)
    {
        LogDebug("CryptoService error with code: " << retCode);
        return CKM_API_ERROR_SERVER_ERROR; // TODO error code
    }

    DBCrypto::Transaction transaction(&handler.database);
    retCode = saveDataHelper(cred,
                            toDBDataType(prv.getType()),
                            aliasPrivate,
                            prv.getDER(),
                            policyPrivate);

    if (CKM_API_SUCCESS != retCode)
        return retCode;

    retCode = saveDataHelper(cred,
                            toDBDataType(pub.getType()),
                            aliasPublic,
                            pub.getDER(),
                            policyPublic);

    if (CKM_API_SUCCESS != retCode)
        return retCode;

    transaction.commit();

    return retCode;
}

RawBuffer CKMLogic::createKeyPair(
    Credentials &cred,
    LogicCommand protocol_cmd,
    int commandId,
    const int additional_param,
    const Alias &aliasPrivate,
    const Alias &aliasPublic,
    const PolicySerializable &policyPrivate,
    const PolicySerializable &policyPublic)
{
    int retCode = CKM_API_SUCCESS;

    KeyType key_type = KeyType::KEY_NONE;
    switch(protocol_cmd)
    {
        case LogicCommand::CREATE_KEY_PAIR_RSA:
            key_type = KeyType::KEY_RSA_PUBLIC;
            break;
        case LogicCommand::CREATE_KEY_PAIR_DSA:
            key_type = KeyType::KEY_DSA_PUBLIC;
            break;
        case LogicCommand::CREATE_KEY_PAIR_ECDSA:
            key_type = KeyType::KEY_ECDSA_PUBLIC;
            break;
        default:
            break;
    }

    try {
        retCode = createKeyPairHelper(
                        cred,
                        key_type,
                        additional_param,
                        aliasPrivate,
                        aliasPublic,
                        policyPrivate,
                        policyPublic);

    } catch (DBCrypto::Exception::AliasExists &e) {
        LogDebug("DBCrypto error: alias exists: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ALIAS_EXISTS;
    } catch (DBCrypto::Exception::TransactionError &e) {
        LogDebug("DBCrypto error: transaction error: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (CKM::CryptoLogic::Exception::Base &e) {
        LogDebug("CryptoLogic error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (DBCrypto::Exception::InternalError &e) {
        LogDebug("DBCrypto internal error: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(protocol_cmd));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);

    return response.Pop();
}

RawBuffer CKMLogic::getCertificateChain(
    Credentials &cred,
    int commandId,
    const RawBuffer &certificate,
    const RawBufferVector &untrustedRawCertVector)
{
    (void)cred;

    CertificateImpl cert(certificate, DataFormat::FORM_DER);
    CertificateImplVector untrustedCertVector;
    CertificateImplVector chainVector;
    RawBufferVector chainRawVector;

    for (auto &e: untrustedRawCertVector)
        untrustedCertVector.push_back(CertificateImpl(e, DataFormat::FORM_DER));

    LogDebug("Cert is empty: " << cert.empty());

    int retCode = m_certStore.verifyCertificate(cert, untrustedCertVector, chainVector);

    if (retCode == CKM_API_SUCCESS) {
        for (auto &e : chainVector)
            chainRawVector.push_back(e.getDER());
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET_CHAIN_CERT));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, chainRawVector);
    return response.Pop();
}

RawBuffer CKMLogic::getCertificateChain(
    Credentials &cred,
    int commandId,
    const RawBuffer &certificate,
    const AliasVector &aliasVector)
{
    int retCode = CKM_API_SUCCESS;
    RawBufferVector chainRawVector;
    try {
        CertificateImpl cert(certificate, DataFormat::FORM_DER);
        CertificateImplVector untrustedCertVector;
        CertificateImplVector chainVector;
        DBRow row;

        if (cert.empty()) {
            retCode = CKM_API_ERROR_SERVER_ERROR;
            goto senderror;
        }

        for (auto &i: aliasVector) {
            retCode = getDataHelper(cred, DBDataType::CERTIFICATE, i, Password(), row);

            if (retCode != CKM_API_SUCCESS)
                goto senderror;

            untrustedCertVector.push_back(CertificateImpl(row.data, DataFormat::FORM_DER));
        }

        retCode = m_certStore.verifyCertificate(cert, untrustedCertVector, chainVector);

        if (retCode != CKM_API_SUCCESS)
            goto senderror;

        for (auto &i: chainVector)
            chainRawVector.push_back(i.getDER());

    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("DBCyptorModule failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::PermissionDenied &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_ACCESS_DENIED;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (...) {
        LogError("Unknown error.");
    }

senderror:
    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET_CHAIN_ALIAS));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, chainRawVector);
    return response.Pop();
}

RawBuffer CKMLogic::createSignature(
        Credentials &cred,
        int commandId,
        const Alias &privateKeyAlias,
        const Password &password,           // password for private_key
        const RawBuffer &message,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding)
{
    DBRow row;
    CryptoService cs;
    RawBuffer signature;

    int retCode = CKM_API_SUCCESS;

    try {
        do {
            retCode = getDataHelper(cred, DBDataType::DB_KEY_FIRST, privateKeyAlias, password, row);
            if (CKM_API_SUCCESS != retCode) {
                LogError("getDataHelper return error");
                break;
            }

            KeyImpl keyParsed(row.data, Password());
            if (keyParsed.empty())
                retCode = CKM_API_ERROR_SERVER_ERROR;
            else
                retCode = cs.createSignature(keyParsed, message, hash, padding, signature);
        } while(0);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::PermissionDenied &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_ACCESS_DENIED;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKM::Exception &e) {
        LogError("Unknown CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::CREATE_SIGNATURE));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);
    Serialization::Serialize(response, signature);
    return response.Pop();
}

RawBuffer CKMLogic::verifySignature(
        Credentials &cred,
        int commandId,
        const Alias &publicKeyOrCertAlias,
        const Password &password,           // password for public_key (optional)
        const RawBuffer &message,
        const RawBuffer &signature,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding)
{
    int retCode = CKM_API_ERROR_VERIFICATION_FAILED;

    try {
        do {
            CryptoService cs;
            DBRow row;
            KeyImpl key;

            retCode = getDataHelper(cred, DBDataType::DB_KEY_FIRST, publicKeyOrCertAlias, password, row);

            if (retCode == CKM_API_SUCCESS) {
                key = KeyImpl(row.data);
            } else if (retCode == CKM_API_ERROR_DB_ALIAS_UNKNOWN) {
                retCode = getDataHelper(cred, DBDataType::CERTIFICATE, publicKeyOrCertAlias, password, row);
                if (retCode != CKM_API_SUCCESS)
                    break;
                CertificateImpl cert(row.data, DataFormat::FORM_DER);
                key = cert.getKeyImpl();
            } else {
                break;
            }

            if (key.empty()) {
                retCode = CKM_API_ERROR_SERVER_ERROR;
                break;
            }

            retCode = cs.verifySignature(key, message, signature, hash, padding);
        } while(0);
    } catch (const CryptoService::Exception::Crypto_internal &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoService::Exception::opensslError &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::PermissionDenied &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_ACCESS_DENIED;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKM::Exception &e) {
        LogError("Unknown CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::VERIFY_SIGNATURE));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, retCode);

    return response.Pop();
}

RawBuffer CKMLogic::allowAccess(
        Credentials &cred,
        int command,
        int msgID,
        const Alias &item_alias,
        const std::string &accessor_label,
        const AccessRight req_rights)
{
    int retCode = CKM_API_ERROR_VERIFICATION_FAILED;

    if (0 < m_userDataMap.count(cred.uid))
    {
        Try {
            retCode = m_userDataMap[cred.uid].database.setAccessRights(cred.smackLabel, item_alias, accessor_label, req_rights);
        } Catch (DBCrypto::Exception::InvalidArgs) {
            LogError("Error: invalid args!");
            retCode = CKM_API_ERROR_INPUT_PARAM;
        } Catch (DBCrypto::Exception::PermissionDenied) {
            LogError("Error: not enough permissions!");
            retCode = CKM_API_ERROR_ACCESS_DENIED;
        } Catch (CKM::Exception) {
            LogError("Error in set row!");
            retCode = CKM_API_ERROR_DB_ERROR;
        }
    } else {
        retCode = CKM_API_ERROR_DB_LOCKED;
    }

    MessageBuffer response;
    Serialization::Serialize(response, command);
    Serialization::Serialize(response, msgID);
    Serialization::Serialize(response, retCode);

    return response.Pop();
}

RawBuffer CKMLogic::denyAccess(
        Credentials &cred,
        int command,
        int msgID,
        const Alias &item_alias,
        const std::string &accessor_label)
{
    int retCode = CKM_API_ERROR_VERIFICATION_FAILED;

    if (0 < m_userDataMap.count(cred.uid))
    {
        Try {
            retCode = m_userDataMap[cred.uid].database.clearAccessRights(cred.smackLabel, item_alias, accessor_label);
        } Catch (DBCrypto::Exception::PermissionDenied) {
            LogError("Error: not enough permissions!");
            retCode = CKM_API_ERROR_ACCESS_DENIED;
        } Catch (DBCrypto::Exception::InvalidArgs) {
            LogError("Error: permission not found!");
            retCode = CKM_API_ERROR_INPUT_PARAM;
        } Catch (CKM::Exception) {
            LogError("Error in deleting row!");
            retCode = CKM_API_ERROR_DB_ERROR;
        }
    } else {
        retCode = CKM_API_ERROR_DB_LOCKED;
    }

    MessageBuffer response;
    Serialization::Serialize(response, command);
    Serialization::Serialize(response, msgID);
    Serialization::Serialize(response, retCode);

    return response.Pop();
}

} // namespace CKM

