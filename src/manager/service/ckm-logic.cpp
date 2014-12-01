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
#include <vconf/vconf.h>
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

bool isLabelValid(const CKM::Label &label) {
    // TODO: copy code from libprivilege control (for check smack label)
    if (label.find(CKM::LABEL_NAME_SEPARATOR) != CKM::Label::npos)
        return false;
    return true;
}

bool isNameValid(const CKM::Name &name) {
    if (name.find(CKM::LABEL_NAME_SEPARATOR) != CKM::Name::npos)
        return false;
    return true;
}

} // anonymous namespace

namespace CKM {

CKMLogic::CKMLogic()
{
    if (CKM_API_SUCCESS != m_certStore.setSystemCertificateDir(CERT_SYSTEM_DIR)) {
        LogError("Fatal error in CertificateStore::setSystemCertificateDir. Chain creation will not work");
    }

    m_accessControl.updateCCMode();
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

    return MessageBuffer::Serialize(retCode).Pop();
}

RawBuffer CKMLogic::updateCCMode() {
    m_accessControl.updateCCMode();
    return MessageBuffer::Serialize(CKM_API_SUCCESS).Pop();
}

RawBuffer CKMLogic::lockUserKey(uid_t user) {
    int retCode = CKM_API_SUCCESS;
    // TODO try catch for all errors that should be supported by error code
    m_userDataMap.erase(user);

    return MessageBuffer::Serialize(retCode).Pop();

}

RawBuffer CKMLogic::removeUserData(uid_t user) {
    int retCode = CKM_API_SUCCESS;
    // TODO try catch for all errors that should be supported by error code
    m_userDataMap.erase(user);

    FileSystem fs(user);
    fs.removeUserData();

    return MessageBuffer::Serialize(retCode).Pop();
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

    return MessageBuffer::Serialize(retCode).Pop();
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

    return MessageBuffer::Serialize(retCode).Pop();
}

RawBuffer CKMLogic::removeApplicationData(const Label &smackLabel) {
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

    return MessageBuffer::Serialize(retCode).Pop();
}

int CKMLogic::saveDataHelper(
    const Credentials &cred,
    DBDataType dataType,
    const Name &name,
    const Label &label,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

    // verify name and label are correct
    if (!isNameValid(name) || !isLabelValid(ownerLabel)) {
        LogWarning("Invalid parameter passed to key-manager");
        return CKM_API_ERROR_INPUT_PARAM;
    }

    // check if allowed to save using ownerLabel
    int access_ec = m_accessControl.canSave(ownerLabel, cred.smackLabel);
    if(access_ec != CKM_API_SUCCESS)
    {
        LogWarning("label " << cred.smackLabel << " can not save rows using label " << ownerLabel);
        return access_ec;
    }

    // proceed to data save
    DBRow row = { name, cred.smackLabel,
         policy.extractable, dataType, DBCMAlgType::NONE,
         0, RawBuffer(), static_cast<int>(key.size()), key, RawBuffer() };

    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    auto &handler = m_userDataMap[cred.uid];
    DBCrypto::Transaction transaction(&handler.database);

    // check if not a duplicate
    if( handler.database.isNameLabelPresent(name, cred.smackLabel) )
        return CKM_API_ERROR_DB_ALIAS_EXISTS;

    // encryption section
    if (!handler.crypto.haveKey(cred.smackLabel)) {
        RawBuffer got_key;
        auto key_optional = handler.database.getKey(cred.smackLabel);
        if(!key_optional) {
            LogDebug("No Key in database found. Generating new one for label: "
                    << cred.smackLabel);
            got_key = handler.keyProvider.generateDEK(cred.smackLabel);
            handler.database.saveKey(cred.smackLabel, got_key);
        } else {
            LogDebug("Key from DB");
            got_key = *key_optional;
        }

        got_key = handler.keyProvider.getPureDEK(got_key);
        handler.crypto.pushKey(cred.smackLabel, got_key);
    }

    // do not encrypt data with password during cc_mode on
    if(m_accessControl.isCCMode()) {
        handler.crypto.encryptRow("", row);
    } else {
        handler.crypto.encryptRow(policy.password, row);
    }

    handler.database.saveDBRow(row);
    transaction.commit();
    return CKM_API_SUCCESS;
}

void CKMLogic::verifyBinaryData(DBDataType dataType, const RawBuffer &input_data) const
{
    // verify the data integrity
    switch(dataType)
    {
        case DBDataType::KEY_RSA_PUBLIC:
        case DBDataType::KEY_RSA_PRIVATE:
        case DBDataType::KEY_ECDSA_PUBLIC:
        case DBDataType::KEY_ECDSA_PRIVATE:
        case DBDataType::KEY_DSA_PUBLIC:
        case DBDataType::KEY_DSA_PRIVATE:
        case DBDataType::KEY_AES:
        {
            KeyShPtr output_key = CKM::Key::create(input_data);
            if(output_key.get() == NULL)
                ThrowMsg(CKMLogic::Exception::InputDataInvalid, "provided binary data is not valid key data");
            break;
        }

        case DBDataType::CERTIFICATE:
        {
            CertificateShPtr cert = CKM::Certificate::create(input_data, DataFormat::FORM_DER);
            if(cert.get() == NULL)
                ThrowMsg(CKMLogic::Exception::InputDataInvalid, "provided binary data is not valid certificate data");
            break;
        }

        // TODO: add here BINARY_DATA verification, i.e: max size etc.

        default: break;
    }
}

RawBuffer CKMLogic::saveData(
    const Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Name &name,
    const Label &label,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    int retCode = CKM_API_SUCCESS;
    try {
        verifyBinaryData(dataType, key);

        retCode = saveDataHelper(cred, dataType, name, label, key, policy);
        LogDebug("SaveDataHelper returned: " << retCode);
    } catch (const CKMLogic::Exception::InputDataInvalid &e) {
        LogError("Provided data invalid: " << e.GetMessage());
        retCode = CKM_API_ERROR_INPUT_PARAM;
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::InternalError &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const DBCrypto::Exception::TransactionError &e) {
        LogError("DBCrypto transaction failed with message " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE),
                                             commandId,
                                             retCode,
                                             static_cast<int>(dataType));
    return response.Pop();
}

int CKMLogic::removeDataHelper(
        const Credentials &cred,
        const Name &name,
        const Label &ownerLabel)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    if (!isNameValid(name) || !isLabelValid(ownerLabel)) {
        LogError("Invalid label or name format");
        return CKM_API_ERROR_INPUT_PARAM;
    }

    auto &database = m_userDataMap[cred.uid].database;
    DBCrypto::Transaction transaction(&database);

    // read and check permissions
    PermissionOptional permissionRowOpt =
            database.getPermissionRow(name, ownerLabel, cred.smackLabel);
    int access_ec = m_accessControl.canDelete(ownerLabel, PermissionForLabel(cred.smackLabel, permissionRowOpt));
    if(access_ec != CKM_API_SUCCESS)
    {
        LogWarning("access control check result: " << access_ec);
        return access_ec;
    }

    auto erased = database.deleteDBRow(name, ownerLabel);
    // check if the data existed or not
    if(erased)
        transaction.commit();
    else {
        LogError("No row for given name and label");
        return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
    }

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::removeData(
    const Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Name &name,
    const Label &label)
{
    int retCode;
    Try {
        // use client label if not explicitly provided
        const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

        retCode = removeDataHelper(cred, name, ownerLabel);
    } Catch (CKM::Exception) {
        LogError("Error in deleting row!");
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::REMOVE),
                                             commandId,
                                             retCode,
                                             static_cast<int>(dataType));
    return response.Pop();
}

int CKMLogic::readDataRowHelper(const Name &name,
                                const Label &ownerLabel,
                                DBDataType dataType,
                                DBCrypto & database,
                                DBRow &row)
{
    // read row
    DBCrypto::DBRowOptional row_optional;
    // TODO: move this check into request deserialization
    if((static_cast<int>(dataType)<static_cast<int>(DBDataType::DB_DATA_TYPE_FIRST)) ||
       (static_cast<int>(dataType)>static_cast<int>(DBDataType::DB_DATA_TYPE_LAST)))
    {
        LogError("Unknown type of requested data: " << (int)dataType);
        return CKM_API_ERROR_BAD_REQUEST;
    }
    // TODO: provide internal type rather than using DB types in socket comms
    else if ((dataType >= DBDataType::DB_KEY_FIRST) &&
             (dataType <= DBDataType::DB_KEY_LAST))
    {
        // read all key types
        row_optional = database.getDBRow(name,
                                         ownerLabel,
                                         DBDataType::DB_KEY_FIRST,
                                         DBDataType::DB_KEY_LAST);
    }
    else {
        // read anything else
        row_optional = database.getDBRow(name,
                                         ownerLabel,
                                         dataType);
    }

    if(!row_optional) {
        LogError("No row for given name, label and type");
        return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
    } else {
        row = *row_optional;
    }

    return CKM_API_SUCCESS;
}

int CKMLogic::checkDataPermissionsHelper(const Name &name,
                                         const Label &ownerLabel,
                                         const Label &accessorLabel,
                                         const DBRow &row,
                                         bool exportFlag,
                                         DBCrypto & database)
{
    PermissionOptional permissionRowOpt =
            database.getPermissionRow(name, ownerLabel, accessorLabel);

    if(exportFlag)
        return m_accessControl.canExport(row, PermissionForLabel(accessorLabel, permissionRowOpt));
    return m_accessControl.canRead(row, PermissionForLabel(accessorLabel, permissionRowOpt));
}

int CKMLogic::readDataHelper(
    bool exportFlag,
    const Credentials &cred,
    DBDataType dataType,
    const Name &name,
    const Label &label,
    const Password &password,
    DBRow &row)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

    if (!isNameValid(name) || !isLabelValid(ownerLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    auto &handler = m_userDataMap[cred.uid];

    // read row
    DBCrypto::Transaction transaction(&handler.database);
    int ec = readDataRowHelper(name, ownerLabel, dataType, handler.database, row);
    if(CKM_API_SUCCESS != ec)
        return ec;


    // check access rights
    ec = checkDataPermissionsHelper(name, ownerLabel, cred.smackLabel, row, exportFlag, handler.database);
    if(CKM_API_SUCCESS != ec)
        return ec;

    // decrypt row
    if (!handler.crypto.haveKey(row.ownerLabel)) {
        RawBuffer key;
        auto key_optional = handler.database.getKey(row.ownerLabel);
        if(!key_optional) {
            LogError("No key for given label in database");
            return CKM_API_ERROR_DB_ERROR;
        }
        key = *key_optional;
        key = handler.keyProvider.getPureDEK(key);
        handler.crypto.pushKey(row.ownerLabel, key);
    }
    handler.crypto.decryptRow(password, row);

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::getData(
    const Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Name &name,
    const Label &label,
    const Password &password)
{
    int retCode = CKM_API_SUCCESS;
    DBRow row;

    try {
        retCode = readDataHelper(true, cred, dataType, name, label, password, row);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    if (CKM_API_SUCCESS != retCode) {
        row.data.clear();
        row.dataType = dataType;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET),
                                             commandId,
                                             retCode,
                                             static_cast<int>(row.dataType),
                                             row.data);
    return response.Pop();
}

RawBuffer CKMLogic::getDataList(
    const Credentials &cred,
    int commandId,
    DBDataType dataType)
{
    int retCode = CKM_API_SUCCESS;
    LabelNameVector labelNameVector;

    if (0 < m_userDataMap.count(cred.uid)) {
        auto &database = m_userDataMap[cred.uid].database;

        Try {
            // list names
            // TODO: move this check into request deserialization
            if((static_cast<int>(dataType)<static_cast<int>(DBDataType::DB_DATA_TYPE_FIRST)) ||
               (static_cast<int>(dataType)>static_cast<int>(DBDataType::DB_DATA_TYPE_LAST)))
            {
                LogError("Unknown type of requested data: " << (int)dataType);
                retCode = CKM_API_ERROR_BAD_REQUEST;
            }
            // TODO: provide internal type rather than using DB types in socket comms
            else if ((dataType >= DBDataType::DB_KEY_FIRST) && (dataType <= DBDataType::DB_KEY_LAST))
            {
                // list all key types
                database.listNames(cred.smackLabel,
                                   labelNameVector,
                                   DBDataType::DB_KEY_FIRST,
                                   DBDataType::DB_KEY_LAST);
            }
            else {
                // list anything else
                database.listNames(cred.smackLabel,
                                   labelNameVector,
                                   dataType);
            }
        }
        Catch (CKM::Exception) {
            LogError("Failed to get names");
            retCode = CKM_API_ERROR_DB_ERROR;
        }
    } else {
        retCode = CKM_API_ERROR_DB_LOCKED;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_LIST),
                                             commandId,
                                             retCode,
                                             static_cast<int>(dataType),
                                             labelNameVector);
    return response.Pop();
}


int CKMLogic::createKeyPairHelper(
    const Credentials &cred,
    const KeyType key_type,
    const int additional_param,
    const Name &namePrivate,
    const Label &labelPrivate,
    const Name &namePublic,
    const Label &labelPublic,
    const PolicySerializable &policyPrivate,
    const PolicySerializable &policyPublic)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

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

    auto &database = m_userDataMap[cred.uid].database;
    DBCrypto::Transaction transaction(&database);
    retCode = saveDataHelper(cred,
                            toDBDataType(prv.getType()),
                            namePrivate,
                            labelPrivate,
                            prv.getDER(),
                            policyPrivate);

    if (CKM_API_SUCCESS != retCode)
        return retCode;

    retCode = saveDataHelper(cred,
                            toDBDataType(pub.getType()),
                            namePublic,
                            labelPublic,
                            pub.getDER(),
                            policyPublic);

    if (CKM_API_SUCCESS != retCode)
        return retCode;

    transaction.commit();

    return retCode;
}

RawBuffer CKMLogic::createKeyPair(
    const Credentials &cred,
    LogicCommand protocol_cmd,
    int commandId,
    const int additional_param,
    const Name &namePrivate,
    const Label &labelPrivate,
    const Name &namePublic,
    const Label &labelPublic,
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
                        namePrivate,
                        labelPrivate,
                        namePublic,
                        labelPublic,
                        policyPrivate,
                        policyPublic);
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

    return MessageBuffer::Serialize(static_cast<int>(protocol_cmd), commandId, retCode).Pop();
}

RawBuffer CKMLogic::getCertificateChain(
    const Credentials &cred,
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

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_CHAIN_CERT),
                                             commandId,
                                             retCode,
                                             chainRawVector);
    return response.Pop();
}

int CKMLogic::getCertificateChainHelper(
        const Credentials &cred,
        const RawBuffer &certificate,
        const LabelNameVector &labelNameVector,
        RawBufferVector & chainRawVector)
{
    CertificateImpl cert(certificate, DataFormat::FORM_DER);
    CertificateImplVector untrustedCertVector;
    CertificateImplVector chainVector;
    DBRow row;

    if (cert.empty())
        return CKM_API_ERROR_SERVER_ERROR;

    for (auto &i: labelNameVector) {
        int ec = readDataHelper(false, cred, DBDataType::CERTIFICATE, i.second, i.first, Password(), row);
        if (ec != CKM_API_SUCCESS)
            return ec;

        untrustedCertVector.push_back(CertificateImpl(row.data, DataFormat::FORM_DER));
    }

    int ec = m_certStore.verifyCertificate(cert, untrustedCertVector, chainVector);
    if (ec != CKM_API_SUCCESS)
        return ec;

    for (auto &i: chainVector)
        chainRawVector.push_back(i.getDER());

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::getCertificateChain(
    const Credentials &cred,
    int commandId,
    const RawBuffer &certificate,
    const LabelNameVector &labelNameVector)
{
    int retCode = CKM_API_SUCCESS;
    RawBufferVector chainRawVector;
    try {

        retCode = getCertificateChainHelper(cred, certificate, labelNameVector, chainRawVector);
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("DBCyptorModule failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (...) {
        LogError("Unknown error.");
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_CHAIN_ALIAS),
                                             commandId,
                                             retCode,
                                             chainRawVector);
    return response.Pop();
}

RawBuffer CKMLogic::createSignature(
        const Credentials &cred,
        int commandId,
        const Name &privateKeyName,
        const Label & ownerLabel,
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
        retCode = readDataHelper(false, cred, DBDataType::DB_KEY_FIRST, privateKeyName, ownerLabel, password, row);
        if(retCode == CKM_API_SUCCESS)
        {
            KeyImpl keyParsed(row.data, Password());
            if (keyParsed.empty())
                retCode = CKM_API_ERROR_SERVER_ERROR;
            else
                retCode = cs.createSignature(keyParsed, message, hash, padding, signature);
        }
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKM::Exception &e) {
        LogError("Unknown CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::CREATE_SIGNATURE),
                                             commandId,
                                             retCode,
                                             signature);
    return response.Pop();
}

RawBuffer CKMLogic::verifySignature(
        const Credentials &cred,
        int commandId,
        const Name &publicKeyOrCertName,
        const Label & ownerLabel,
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

            retCode = readDataHelper(false, cred, DBDataType::DB_KEY_FIRST, publicKeyOrCertName, ownerLabel, password, row);

            if (retCode == CKM_API_SUCCESS) {
                key = KeyImpl(row.data);
            } else if (retCode == CKM_API_ERROR_DB_ALIAS_UNKNOWN) {
                retCode = readDataHelper(false, cred, DBDataType::CERTIFICATE, publicKeyOrCertName, ownerLabel, password, row);
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
    } catch (const DBCrypto::Exception::Base &e) {
        LogError("DBCrypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKM::Exception &e) {
        LogError("Unknown CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::VERIFY_SIGNATURE),
                                             commandId,
                                             retCode);
    return response.Pop();
}

int CKMLogic::setPermissionHelper(
        const Credentials &cred,
        const Name &name,
        const Label &label,
        const Label &accessorLabel,
        const Permission reqRights)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    if(cred.smackLabel.empty() || cred.smackLabel==accessorLabel)
        return CKM_API_ERROR_INPUT_PARAM;

    // use client label if not explicitly provided
    const Label& ownerLabel = label.empty() ? cred.smackLabel : label;

    // verify name and label are correct
    if (!isNameValid(name) || !isLabelValid(ownerLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    int access_ec = m_accessControl.canModify(ownerLabel, cred.smackLabel);
    if(access_ec != CKM_API_SUCCESS)
        return access_ec;

    auto &database = m_userDataMap[cred.uid].database;
    DBCrypto::Transaction transaction(&database);

    if( ! database.isNameLabelPresent(name, ownerLabel) )
        return CKM_API_ERROR_DB_ALIAS_UNKNOWN;

    // removing non-existing permissions: fail
    if(reqRights == Permission::NONE)
    {
        if( !database.getPermissionRow(name, ownerLabel, accessorLabel) )
            return CKM_API_ERROR_INPUT_PARAM;
    }

    int retCode = database.setPermission(name,
                                     ownerLabel,
                                     accessorLabel,
                                     reqRights);

    transaction.commit();

    return retCode;
}

RawBuffer CKMLogic::setPermission(
        const Credentials &cred,
        int command,
        int msgID,
        const Name &name,
        const Label &label,
        const Label &accessorLabel,
        const Permission reqRights)
{
    int retCode;
    Try {
        retCode = setPermissionHelper(cred, name, label, accessorLabel, reqRights);
    } Catch (CKM::Exception) {
        LogError("Error in set row!");
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    return MessageBuffer::Serialize(command, msgID, retCode).Pop();
}

} // namespace CKM

