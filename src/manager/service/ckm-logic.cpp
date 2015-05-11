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
#include <key-impl.h>
#include <certificate-config.h>
#include <certificate-store.h>

#include <sw-backend/crypto-service.h>

namespace {
const char * const CERT_SYSTEM_DIR  = "/etc/ssl/certs";
const uid_t        SYSTEM_DB_UID    = 0;
const char * const SYSTEM_DB_PASSWD = "cAtRugU7";

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
    CertificateConfig::addSystemCertificateDir(CERT_SYSTEM_DIR);

    m_accessControl.updateCCMode();
}

CKMLogic::~CKMLogic(){}

void CKMLogic::loadDKEKFile(uid_t user, const Password &password) {
    auto &handle = m_userDataMap[user];

    FileSystem fs(user);

    auto wrappedDKEK = fs.getDKEK();

    if (wrappedDKEK.empty()) {
        wrappedDKEK = KeyProvider::generateDomainKEK(std::to_string(user), password);
        fs.saveDKEK(wrappedDKEK);
    }

    handle.keyProvider = KeyProvider(wrappedDKEK, password);
}

void CKMLogic::saveDKEKFile(uid_t user, const Password &password) {
    auto &handle = m_userDataMap[user];

    FileSystem fs(user);
    fs.saveDKEK(handle.keyProvider.getWrappedDomainKEK(password));
}

int CKMLogic::unlockDatabase(uid_t user, const Password & password)
{
    if (0<m_userDataMap.count(user) && m_userDataMap[user].keyProvider.isInitialized())
        return CKM_API_SUCCESS;

    int retCode = CKM_API_SUCCESS;
    try
    {
        auto &handle = m_userDataMap[user];

        FileSystem fs(user);
        loadDKEKFile(user, password);

        auto wrappedDatabaseDEK = fs.getDBDEK();
        if (wrappedDatabaseDEK.empty()) {
            wrappedDatabaseDEK = handle.keyProvider.generateDEK(std::to_string(user));
            fs.saveDBDEK(wrappedDatabaseDEK);
        }

        RawBuffer key = handle.keyProvider.getPureDEK(wrappedDatabaseDEK);

        handle.database = DB::Crypto(fs.getDBPath(), key);
        handle.crypto = CryptoLogic();

        if ( !m_accessControl.isSystemService(user) )
        {
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
    } catch (const FileSystem::Exception::Base &e) {
        LogError("FileSystem error: " << e.GetMessage());
        retCode = CKM_API_ERROR_FILE_SYSTEM;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    if (CKM_API_SUCCESS != retCode)
        m_userDataMap.erase(user);

    return retCode;
}

int CKMLogic::unlockSystemDB()
{
    return unlockDatabase(SYSTEM_DB_UID, SYSTEM_DB_PASSWD);
}

UserData & CKMLogic::selectDatabase(const Credentials &cred, const Label &incoming_label)
{
    // if user trying to access system service - check:
    //    * if user database is unlocked [mandatory]
    //    * if not - proceed with regular user database
    //    * if explicit system database label given -> switch to system DB
    if ( !m_accessControl.isSystemService(cred) )
    {
        if (0 == m_userDataMap.count(cred.clientUid))
            ThrowMsg(Exception::DatabaseLocked, "database with UID: " << cred.clientUid << " locked");

        if (0 != incoming_label.compare(LABEL_SYSTEM_DB))
            return m_userDataMap[cred.clientUid];
    }

    // system database selected, modify the label
    if (CKM_API_SUCCESS != unlockSystemDB() )
        ThrowMsg(Exception::DatabaseLocked, "can not unlock system database");
    return m_userDataMap[SYSTEM_DB_UID];
}

RawBuffer CKMLogic::unlockUserKey(uid_t user, const Password &password)
{
    int retCode = CKM_API_SUCCESS;

    if( !m_accessControl.isSystemService(user) )
    {
        retCode = unlockDatabase(user, password);
    }
    else
    {
        // do not allow lock/unlock operations for system users
        retCode = CKM_API_ERROR_INPUT_PARAM;
    }

    return MessageBuffer::Serialize(retCode).Pop();
}

RawBuffer CKMLogic::updateCCMode() {
    m_accessControl.updateCCMode();
    return MessageBuffer::Serialize(CKM_API_SUCCESS).Pop();
}

RawBuffer CKMLogic::lockUserKey(uid_t user)
{
    int retCode = CKM_API_SUCCESS;
    if( !m_accessControl.isSystemService(user) )
    {
        m_userDataMap.erase(user);
    }
    else
    {
        // do not allow lock/unlock operations for system users
        retCode = CKM_API_ERROR_INPUT_PARAM;
    }

    return MessageBuffer::Serialize(retCode).Pop();

}

RawBuffer CKMLogic::removeUserData(uid_t user) {
    int retCode = CKM_API_SUCCESS;

    if (m_accessControl.isSystemService(user))
        user = SYSTEM_DB_UID;

    m_userDataMap.erase(user);

    FileSystem fs(user);
    fs.removeUserData();

    return MessageBuffer::Serialize(retCode).Pop();
}

int CKMLogic::changeUserPasswordHelper(uid_t user,
                                       const Password &oldPassword,
                                       const Password &newPassword)
{
    // do not allow to change system database password
    if( m_accessControl.isSystemService(user) )
        return CKM_API_ERROR_INPUT_PARAM;

    loadDKEKFile(user, oldPassword);
    saveDKEKFile(user, newPassword);

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::changeUserPassword(
    uid_t user,
    const Password &oldPassword,
    const Password &newPassword)
{
    int retCode = CKM_API_SUCCESS;
    try
    {
        retCode = changeUserPasswordHelper(user, oldPassword, newPassword);
    } catch (const KeyProvider::Exception::PassWordError &e) {
        LogError("Incorrect Password " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("Error in KeyProvider " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const FileSystem::Exception::Base &e) {
        LogError("Error in FileSystem " << e.GetMessage());
        retCode = CKM_API_ERROR_FILE_SYSTEM;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    return MessageBuffer::Serialize(retCode).Pop();
}

int CKMLogic::resetUserPasswordHelper(
    uid_t user,
    const Password &newPassword)
{
    // do not allow to reset system database password
    if( m_accessControl.isSystemService(user) )
        return CKM_API_ERROR_INPUT_PARAM;

    int retCode = CKM_API_SUCCESS;
    if (0 == m_userDataMap.count(user))
    {
        // Check if key exists. If exists we must return error
        FileSystem fs(user);
        auto wrappedDKEKMain = fs.getDKEK();
        if (!wrappedDKEKMain.empty())
            retCode = CKM_API_ERROR_BAD_REQUEST;
    } else {
        saveDKEKFile(user, newPassword);
    }

    return retCode;
}

RawBuffer CKMLogic::resetUserPassword(
    uid_t user,
    const Password &newPassword)
{
    int retCode = CKM_API_SUCCESS;
    try {
        retCode = resetUserPasswordHelper(user, newPassword);
    } catch (const FileSystem::Exception::Base &e) {
        LogError("Error in FileSystem " << e.GetMessage());
        retCode = CKM_API_ERROR_FILE_SYSTEM;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
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

    } catch (const DB::Crypto::Exception::InternalError &e) {
        LogError("DB::Crypto couldn't remove data: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const DB::Crypto::Exception::TransactionError &e) {
        LogError("DB::Crypto transaction failed with message " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const FileSystem::Exception::Base &e) {
        LogError("Error in FileSystem " << e.GetMessage());
        retCode = CKM_API_ERROR_FILE_SYSTEM;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    return MessageBuffer::Serialize(retCode).Pop();
}

int CKMLogic::checkSaveConditions(
    const Credentials &cred,
    UserData &handler,
    const Name &name,
    const Label &ownerLabel)
{
    // verify name and label are correct
    if (!isNameValid(name) || !isLabelValid(ownerLabel)) {
        LogWarning("Invalid parameter passed to key-manager");
        return CKM_API_ERROR_INPUT_PARAM;
    }

    // check if allowed to save using ownerLabel
    int access_ec = m_accessControl.canSave(cred, ownerLabel);
    if( access_ec != CKM_API_SUCCESS)
    {
        LogWarning("label " << cred.smackLabel << " can not save rows using label " << ownerLabel);
        return access_ec;
    }

    // check if not a duplicate
    if( handler.database.isNameLabelPresent(name, ownerLabel))
        return CKM_API_ERROR_DB_ALIAS_EXISTS;

    // encryption section
    if (!handler.crypto.haveKey(ownerLabel))
    {
        RawBuffer got_key;
        auto key_optional = handler.database.getKey(ownerLabel);
        if(!key_optional) {
            LogDebug("No Key in database found. Generating new one for label: " << ownerLabel);
            got_key = handler.keyProvider.generateDEK(ownerLabel);
            handler.database.saveKey(ownerLabel, got_key);
        } else {
            LogDebug("Key from DB");
            got_key = *key_optional;
        }

        got_key = handler.keyProvider.getPureDEK(got_key);
        handler.crypto.pushKey(ownerLabel, got_key);
    }

    return CKM_API_SUCCESS;
}

DB::Row CKMLogic::createEncryptedRow(
    CryptoLogic &crypto,
    const Name &name,
    const Label &label,
    DataType dataType,
    const RawBuffer &data,
    const Policy &policy) const
{
    DB::Row row(name, label, static_cast<int>(policy.extractable), dataType, data, static_cast<int>(data.size()));

    // do not encrypt data with password during cc_mode on
    if(m_accessControl.isCCMode()) {
        crypto.encryptRow("", row);
    } else {
        crypto.encryptRow(policy.password, row);
    }
    return row;
}

int CKMLogic::verifyBinaryData(DataType dataType, const RawBuffer &input_data) const
{
    // verify the data integrity
    if (dataType.isKey())
    {
        KeyShPtr output_key = CKM::Key::create(input_data);
        if(output_key.get() == NULL)
        {
            LogError("provided binary data is not valid key data");
            return CKM_API_ERROR_INPUT_PARAM;
        }
    }
    else if (dataType.isCertificate() || dataType.isChainCert())
    {
        CertificateShPtr cert = CKM::Certificate::create(input_data, DataFormat::FORM_DER);
        if(cert.get() == NULL)
        {
            LogError("provided binary data is not valid certificate data");
            return CKM_API_ERROR_INPUT_PARAM;
        }
    }
    // TODO: add here BINARY_DATA verification, i.e: max size etc.
    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::saveData(
    const Credentials &cred,
    int commandId,
    const Name &name,
    const Label &label,
    const RawBuffer &data,
    DataType dataType,
    const PolicySerializable &policy)
{
    int retCode = CKM_API_ERROR_UNKNOWN;

    try {
        // check if data is correct
        retCode = verifyBinaryData(dataType, data);
        if(retCode == CKM_API_SUCCESS)
        {
            retCode = saveDataHelper(cred, name, label, dataType, data, policy);
        }
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::InternalError &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const DB::Crypto::Exception::TransactionError &e) {
        LogError("DB::Crypto transaction failed with message " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const FileSystem::Exception::Base &e) {
        LogError("Error in FileSystem " << e.GetMessage());
        retCode = CKM_API_ERROR_FILE_SYSTEM;
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE),
                                             commandId,
                                             retCode,
                                             static_cast<int>(dataType));
    return response.Pop();
}

int CKMLogic::extractPKCS12Data(
    CryptoLogic &crypto,
    const Name &name,
    const Label &ownerLabel,
    const PKCS12Serializable &pkcs,
    const PolicySerializable &keyPolicy,
    const PolicySerializable &certPolicy,
    DB::RowVector &output) const
{
    // private key is mandatory
    if( !pkcs.getKey() )
        return CKM_API_ERROR_INVALID_FORMAT;
    Key* keyPtr = pkcs.getKey().get();
    DataType keyType = DataType(keyPtr->getType());
    RawBuffer keyData = keyPtr->getDER();
    int retCode = verifyBinaryData(keyType, keyData);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    output.push_back(createEncryptedRow(crypto, name, ownerLabel, keyType, keyData, keyPolicy));

    // certificate is mandatory
    if( !pkcs.getCertificate() )
        return CKM_API_ERROR_INVALID_FORMAT;
    RawBuffer certData = pkcs.getCertificate().get()->getDER();
    retCode = verifyBinaryData(DataType::CERTIFICATE, certData);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    output.push_back(createEncryptedRow(crypto, name, ownerLabel, DataType::CERTIFICATE, certData, certPolicy));

    // CA cert chain
    unsigned int cert_index = 0;
    for(const auto & ca : pkcs.getCaCertificateShPtrVector())
    {
        DataType chainDataType = DataType::getChainDatatype(cert_index ++);
        RawBuffer caCertData = ca->getDER();
        int retCode = verifyBinaryData(chainDataType, caCertData);
        if(retCode != CKM_API_SUCCESS)
            return retCode;

        output.push_back(createEncryptedRow(crypto, name, ownerLabel, chainDataType, caCertData, certPolicy));
    }

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::savePKCS12(
    const Credentials &cred,
    int commandId,
    const Name &name,
    const Label &label,
    const PKCS12Serializable &pkcs,
    const PolicySerializable &keyPolicy,
    const PolicySerializable &certPolicy)
{
    int retCode = CKM_API_ERROR_UNKNOWN;
    try {
        retCode = saveDataHelper(cred, name, label, pkcs, keyPolicy, certPolicy);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::InternalError &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const DB::Crypto::Exception::TransactionError &e) {
        LogError("DB::Crypto transaction failed with message " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE_PKCS12),
                                             commandId,
                                             retCode);
    return response.Pop();
}


int CKMLogic::removeDataHelper(
        const Credentials &cred,
        const Name &name,
        const Label &label)
{
    auto &handler = selectDatabase(cred, label);

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;
    if (!isNameValid(name) || !isLabelValid(ownerLabel)) {
        LogError("Invalid label or name format");
        return CKM_API_ERROR_INPUT_PARAM;
    }

    DB::Crypto::Transaction transaction(&handler.database);

    // read and check permissions
    PermissionMaskOptional permissionRowOpt =
            handler.database.getPermissionRow(name, ownerLabel, cred.smackLabel);
    int retCode = m_accessControl.canDelete(cred,
                        PermissionForLabel(cred.smackLabel, permissionRowOpt));
    if(retCode != CKM_API_SUCCESS)
    {
        LogWarning("access control check result: " << retCode);
        return retCode;
    }

    auto erased = handler.database.deleteRow(name, ownerLabel);
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
    const Name &name,
    const Label &label)
{
    int retCode = CKM_API_ERROR_UNKNOWN;

    try
    {
        retCode = removeDataHelper(cred, name, label);
    }
    catch (const CKMLogic::Exception::DatabaseLocked &e)
    {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
    }
    catch (const CKM::Exception &)
    {
        LogError("Error in deleting row!");
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::REMOVE),
                                             commandId,
                                             retCode);
    return response.Pop();
}

int CKMLogic::readSingleRow(const Name &name,
                            const Label &ownerLabel,
                            DataType dataType,
                            DB::Crypto & database,
                            DB::Row &row)
{
    DB::Crypto::RowOptional row_optional;
    if (dataType.isKey())
    {
        // read all key types
        row_optional = database.getRow(name,
                                         ownerLabel,
                                         DataType::DB_KEY_FIRST,
                                         DataType::DB_KEY_LAST);
    } else {
        // read anything else
        row_optional = database.getRow(name,
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


int CKMLogic::readMultiRow(const Name &name,
                           const Label &ownerLabel,
                           DataType dataType,
                           DB::Crypto & database,
                           DB::RowVector &output)
{
    if (dataType.isKey())
    {
        // read all key types
        database.getRows(name,
                          ownerLabel,
                          DataType::DB_KEY_FIRST,
                          DataType::DB_KEY_LAST,
                          output);
    }
    else if (dataType.isChainCert())
    {
        // read all key types
        database.getRows(name,
                         ownerLabel,
                         DataType::DB_CHAIN_FIRST,
                         DataType::DB_CHAIN_LAST,
                         output);
    }
    else
    {
        // read anything else
        database.getRows(name,
                         ownerLabel,
                         dataType,
                         output);
    }

    if(!output.size()) {
        LogError("No row for given name, label and type");
        return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
    }

    return CKM_API_SUCCESS;
}

int CKMLogic::checkDataPermissionsHelper(const Credentials &cred,
                                         const Name &name,
                                         const Label &ownerLabel,
                                         const Label &accessorLabel,
                                         const DB::Row &row,
                                         bool exportFlag,
                                         DB::Crypto & database)
{
    PermissionMaskOptional permissionRowOpt =
            database.getPermissionRow(name, ownerLabel, accessorLabel);

    if(exportFlag)
        return m_accessControl.canExport(cred, row, PermissionForLabel(accessorLabel, permissionRowOpt));
    return m_accessControl.canRead(cred, PermissionForLabel(accessorLabel, permissionRowOpt));
}

int CKMLogic::readDataHelper(
    bool exportFlag,
    const Credentials &cred,
    DataType dataType,
    const Name &name,
    const Label &label,
    const Password &password,
    DB::RowVector &rows)
{
    auto &handler = selectDatabase(cred, label);

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

    if (!isNameValid(name) || !isLabelValid(ownerLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    // read rows
    DB::Crypto::Transaction transaction(&handler.database);
    int retCode = readMultiRow(name, ownerLabel, dataType, handler.database, rows);
    if(CKM_API_SUCCESS != retCode)
        return retCode;

    // all read rows belong to the same owner
    DB::Row & firstRow = rows.at(0);

    // check access rights
    retCode = checkDataPermissionsHelper(cred, name, ownerLabel, cred.smackLabel, firstRow, exportFlag, handler.database);
    if(CKM_API_SUCCESS != retCode)
        return retCode;

    // decrypt row
    if (!handler.crypto.haveKey(firstRow.ownerLabel)) {
        RawBuffer key;
        auto key_optional = handler.database.getKey(firstRow.ownerLabel);
        if(!key_optional) {
            LogError("No key for given label in database");
            return CKM_API_ERROR_DB_ERROR;
        }
        key = *key_optional;
        key = handler.keyProvider.getPureDEK(key);
        handler.crypto.pushKey(firstRow.ownerLabel, key);
    }
    for(auto &row : rows)
        handler.crypto.decryptRow(password, row);

    return CKM_API_SUCCESS;
}

int CKMLogic::readDataHelper(
    bool exportFlag,
    const Credentials &cred,
    DataType dataType,
    const Name &name,
    const Label &label,
    const Password &password,
    DB::Row &row)
{
    auto &handler = selectDatabase(cred, label);

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

    if (!isNameValid(name) || !isLabelValid(ownerLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    // read row
    DB::Crypto::Transaction transaction(&handler.database);
    int retCode = readSingleRow(name, ownerLabel, dataType, handler.database, row);
    if(CKM_API_SUCCESS != retCode)
        return retCode;

    // check access rights
    retCode = checkDataPermissionsHelper(cred, name, ownerLabel, cred.smackLabel, row, exportFlag, handler.database);
    if(CKM_API_SUCCESS != retCode)
        return retCode;

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
    DataType dataType,
    const Name &name,
    const Label &label,
    const Password &password)
{
    int retCode = CKM_API_SUCCESS;
    DB::Row row;

    try {
        retCode = readDataHelper(true, cred, dataType, name, label, password, row);
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::DecryptDBRowError &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::Base &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
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

int CKMLogic::getPKCS12Helper(
    const Credentials &cred,
    const Name &name,
    const Label &label,
    const Password &keyPassword,
    const Password &certPassword,
    KeyShPtr & privKey,
    CertificateShPtr & cert,
    CertificateShPtrVector & caChain)
{
    int retCode;

    // read private key (mandatory)
    DB::Row privKeyRow;
    retCode = readDataHelper(true, cred, DataType::DB_KEY_FIRST, name, label, keyPassword, privKeyRow);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    privKey = CKM::Key::create(privKeyRow.data);

    // read certificate (mandatory)
    DB::Row certRow;
    retCode = readDataHelper(true, cred, DataType::CERTIFICATE, name, label, certPassword, certRow);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    cert = CKM::Certificate::create(certRow.data, DataFormat::FORM_DER);

    // read CA cert chain (optional)
    DB::RowVector rawCaChain;
    retCode = readDataHelper(true, cred, DataType::DB_CHAIN_FIRST, name, label, certPassword, rawCaChain);
    if(retCode != CKM_API_SUCCESS &&
       retCode != CKM_API_ERROR_DB_ALIAS_UNKNOWN)
        return retCode;
    for(auto &rawCaCert : rawCaChain)
        caChain.push_back(CKM::Certificate::create(rawCaCert.data, DataFormat::FORM_DER));

    // if anything found, return it
    if(privKey || cert || caChain.size()>0)
        retCode = CKM_API_SUCCESS;

    return retCode;
}

RawBuffer CKMLogic::getPKCS12(
        const Credentials &cred,
        int commandId,
        const Name &name,
        const Label &label,
        const Password &keyPassword,
        const Password &certPassword)
{
    int retCode = CKM_API_ERROR_UNKNOWN;

    PKCS12Serializable output;
    try {
        KeyShPtr privKey;
        CertificateShPtr cert;
        CertificateShPtrVector caChain;
        retCode = getPKCS12Helper(cred, name, label, keyPassword, certPassword, privKey, cert, caChain);

        // prepare response
        if(retCode == CKM_API_SUCCESS)
            output = PKCS12Serializable(privKey, cert, caChain);

    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::DecryptDBRowError &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::Base &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_PKCS12),
                                             commandId,
                                             retCode,
                                             output);
    return response.Pop();
}

int CKMLogic::getDataListHelper(const Credentials &cred,
                                const DataType dataType,
                                LabelNameVector &labelNameVector)
{
    int retCode = CKM_API_ERROR_DB_LOCKED;
    if (0 < m_userDataMap.count(cred.clientUid))
    {
        auto &database = m_userDataMap[cred.clientUid].database;

        Try {
            LabelNameVector tmpVector;
            if (dataType.isKey()) {
                // list all key types
                database.listNames(cred.smackLabel,
                                   tmpVector,
                                   DataType::DB_KEY_FIRST,
                                   DataType::DB_KEY_LAST);
            } else {
                // list anything else
                database.listNames(cred.smackLabel,
                                   tmpVector,
                                   dataType);
            }
            labelNameVector.insert(labelNameVector.end(), tmpVector.begin(), tmpVector.end());
            retCode = CKM_API_SUCCESS;
        }
        Catch (CKM::Exception) {
            LogError("Failed to get names");
            retCode = CKM_API_ERROR_DB_ERROR;
        }
    }
    return retCode;
}

RawBuffer CKMLogic::getDataList(
    const Credentials &cred,
    int commandId,
    DataType dataType)
{
    LabelNameVector systemVector;
    LabelNameVector userVector;
    LabelNameVector labelNameVector;

    int retCode = unlockSystemDB();
    if (CKM_API_SUCCESS == retCode)
    {
        // system database
        if (m_accessControl.isSystemService(cred))
        {
            // lookup system DB
            retCode = getDataListHelper(Credentials(SYSTEM_DB_UID,
                                                    LABEL_SYSTEM_DB),
                                        dataType,
                                        systemVector);
        }
        else
        {
            // user - lookup system, then client DB
            retCode = getDataListHelper(Credentials(SYSTEM_DB_UID,
                                                    cred.smackLabel),
                                        dataType,
                                        systemVector);

            // private database
            if(retCode == CKM_API_SUCCESS)
            {
                retCode = getDataListHelper(cred,
                                            dataType,
                                            userVector);
            }
        }
    }

    if(retCode == CKM_API_SUCCESS)
    {
        labelNameVector.insert(labelNameVector.end(), systemVector.begin(), systemVector.end());
        labelNameVector.insert(labelNameVector.end(), userVector.begin(), userVector.end());
    }
    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_LIST),
                                             commandId,
                                             retCode,
                                             static_cast<int>(dataType),
                                             labelNameVector);
    return response.Pop();
}

int CKMLogic::saveDataHelper(
    const Credentials &cred,
    const Name &name,
    const Label &label,
    DataType dataType,
    const RawBuffer &data,
    const PolicySerializable &policy)
{
    auto &handler = selectDatabase(cred, label);

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;
    if( m_accessControl.isSystemService(cred) && ownerLabel.compare(LABEL_SYSTEM_DB)!=0)
        return CKM_API_ERROR_INPUT_PARAM;

    // check if save is possible
    DB::Crypto::Transaction transaction(&handler.database);
    int retCode = checkSaveConditions(cred, handler, name, ownerLabel);
    if(retCode != CKM_API_SUCCESS)
        return retCode;

    // save the data
    DB::Row encryptedRow = createEncryptedRow(handler.crypto, name, ownerLabel, dataType, data, policy);
    handler.database.saveRow(encryptedRow);

    transaction.commit();
    return CKM_API_SUCCESS;
}

int CKMLogic::saveDataHelper(
    const Credentials &cred,
    const Name &name,
    const Label &label,
    const PKCS12Serializable &pkcs,
    const PolicySerializable &keyPolicy,
    const PolicySerializable &certPolicy)
{
    auto &handler = selectDatabase(cred, label);

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;
    if( m_accessControl.isSystemService(cred) && ownerLabel.compare(LABEL_SYSTEM_DB)!=0)
        return CKM_API_ERROR_INPUT_PARAM;

    // check if save is possible
    DB::Crypto::Transaction transaction(&handler.database);
    int retCode = checkSaveConditions(cred, handler, name, ownerLabel);
    if(retCode != CKM_API_SUCCESS)
        return retCode;

    // extract and encrypt the data
    DB::RowVector encryptedRows;
    retCode = extractPKCS12Data(handler.crypto, name, ownerLabel, pkcs, keyPolicy, certPolicy, encryptedRows);
    if(retCode != CKM_API_SUCCESS)
        return retCode;

    // save the data
    handler.database.saveRows(name, ownerLabel, encryptedRows);
    transaction.commit();

    return CKM_API_SUCCESS;
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
    auto &handlerPriv = selectDatabase(cred, labelPrivate);
    auto &handlerPub = selectDatabase(cred, labelPublic);


    int retCode;
    KeyImpl prv, pub;
    switch(key_type)
    {
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_RSA_PRIVATE:
            retCode = Crypto::SW::CryptoService::createKeyPairRSA(additional_param, prv, pub);
            break;

        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_DSA_PRIVATE:
            retCode = Crypto::SW::CryptoService::createKeyPairDSA(additional_param, prv, pub);
            break;

        case KeyType::KEY_ECDSA_PUBLIC:
        case KeyType::KEY_ECDSA_PRIVATE:
            retCode = Crypto::SW::CryptoService::createKeyPairECDSA(static_cast<ElipticCurve>(additional_param), prv, pub);
            break;

        default:
            return CKM_API_ERROR_INPUT_PARAM;
    }

    if (CKM_CRYPTO_CREATEKEY_SUCCESS != retCode)
    {
        LogDebug("CryptoService error with code: " << retCode);
        return CKM_API_ERROR_SERVER_ERROR; // TODO error code
    }

    DB::Crypto::Transaction transactionPriv(&handlerPriv.database);
    // in case the same database is used for private and public - the second
    // transaction will not be executed
    DB::Crypto::Transaction transactionPub(&handlerPub.database);

    retCode = saveDataHelper(cred,
                             namePrivate,
                             labelPrivate,
                             DataType(prv.getType()),
                             prv.getDER(),
                             policyPrivate);
    if (CKM_API_SUCCESS != retCode)
        return retCode;

    retCode = saveDataHelper(cred,
                             namePublic,
                             labelPublic,
                             DataType(pub.getType()),
                             pub.getDER(),
                             policyPublic);
    if (CKM_API_SUCCESS != retCode)
        return retCode;

    transactionPub.commit();
    transactionPriv.commit();

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
    } catch (DB::Crypto::Exception::TransactionError &e) {
        LogDebug("DB::Crypto error: transaction error: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (CKM::CryptoLogic::Exception::Base &e) {
        LogDebug("CryptoLogic error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (DB::Crypto::Exception::InternalError &e) {
        LogDebug("DB::Crypto internal error: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
    } catch (const CKM::Exception &e) {
        LogError("CKM::Exception: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    }

    return MessageBuffer::Serialize(static_cast<int>(protocol_cmd), commandId, retCode).Pop();
}

int CKMLogic::readCertificateHelper(
        const Credentials &cred,
        const LabelNameVector &labelNameVector,
        CertificateImplVector &certVector)
{
    DB::Row row;
    for (auto &i: labelNameVector) {
        int ec = readDataHelper(false, cred, DataType::CERTIFICATE, i.second, i.first, Password(), row);
        if (ec != CKM_API_SUCCESS)
            return ec;
        certVector.push_back(CertificateImpl(row.data, DataFormat::FORM_DER));

        // try to read chain certificates (if present)
        DB::RowVector rawCaChain;
        ec = readDataHelper(false, cred, DataType::DB_CHAIN_FIRST, i.second, i.first, CKM::Password(), rawCaChain);
        if(ec != CKM_API_SUCCESS && ec != CKM_API_ERROR_DB_ALIAS_UNKNOWN)
            return ec;
        for(auto &rawCaCert : rawCaChain)
            certVector.push_back(CertificateImpl(rawCaCert.data, DataFormat::FORM_DER));
    }
    return CKM_API_SUCCESS;
}

int CKMLogic::getCertificateChainHelper(
        const CertificateImpl &cert,
        const RawBufferVector &untrustedCertificates,
        const RawBufferVector &trustedCertificates,
        bool useTrustedSystemCertificates,
        RawBufferVector &chainRawVector)
{
    CertificateImplVector untrustedCertVector;
    CertificateImplVector trustedCertVector;
    CertificateImplVector chainVector;

    if (cert.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    for (auto &e: untrustedCertificates)
        untrustedCertVector.push_back(CertificateImpl(e, DataFormat::FORM_DER));
    for (auto &e: trustedCertificates)
        trustedCertVector.push_back(CertificateImpl(e, DataFormat::FORM_DER));

    CertificateStore store;
    int retCode = store.verifyCertificate(cert,
                                          untrustedCertVector,
                                          trustedCertVector,
                                          useTrustedSystemCertificates,
                                          m_accessControl.isCCMode(),
                                          chainVector);
    if (retCode != CKM_API_SUCCESS)
        return retCode;

    for (auto &e : chainVector)
        chainRawVector.push_back(e.getDER());
    return CKM_API_SUCCESS;
}

int CKMLogic::getCertificateChainHelper(
        const Credentials &cred,
        const CertificateImpl &cert,
        const LabelNameVector &untrusted,
        const LabelNameVector &trusted,
        bool useTrustedSystemCertificates,
        RawBufferVector &chainRawVector)
{
    CertificateImplVector untrustedCertVector;
    CertificateImplVector trustedCertVector;
    CertificateImplVector chainVector;
    DB::Row row;

    if (cert.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    int retCode = readCertificateHelper(cred, untrusted, untrustedCertVector);
    if (retCode != CKM_API_SUCCESS)
        return retCode;
    retCode = readCertificateHelper(cred, trusted, trustedCertVector);
    if (retCode != CKM_API_SUCCESS)
        return retCode;

    CertificateStore store;
    retCode = store.verifyCertificate(cert,
                                      untrustedCertVector,
                                      trustedCertVector,
                                      useTrustedSystemCertificates,
                                      m_accessControl.isCCMode(),
                                      chainVector);
    if (retCode != CKM_API_SUCCESS)
        return retCode;

    for (auto &i: chainVector)
        chainRawVector.push_back(i.getDER());

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::getCertificateChain(
    const Credentials & /*cred*/,
    int commandId,
    const RawBuffer &certificate,
    const RawBufferVector &untrustedCertificates,
    const RawBufferVector &trustedCertificates,
    bool useTrustedSystemCertificates)
{
    CertificateImpl cert(certificate, DataFormat::FORM_DER);
    RawBufferVector chainRawVector;
    int retCode = CKM_API_ERROR_UNKNOWN;
    try {
        retCode = getCertificateChainHelper(cert,
                                            untrustedCertificates,
                                            trustedCertificates,
                                            useTrustedSystemCertificates,
                                            chainRawVector);
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::Base &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const std::exception& e) {
        LogError("STD exception " << e.what());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (...) {
        LogError("Unknown error.");
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_CHAIN_CERT),
                                             commandId,
                                             retCode,
                                             chainRawVector);
    return response.Pop();
}

RawBuffer CKMLogic::getCertificateChain(
    const Credentials &cred,
    int commandId,
    const RawBuffer &certificate,
    const LabelNameVector &untrustedCertificates,
    const LabelNameVector &trustedCertificates,
    bool useTrustedSystemCertificates)
{
    int retCode = CKM_API_ERROR_UNKNOWN;
    CertificateImpl cert(certificate, DataFormat::FORM_DER);
    RawBufferVector chainRawVector;
    try {
        retCode = getCertificateChainHelper(cred,
                                            cert,
                                            untrustedCertificates,
                                            trustedCertificates,
                                            useTrustedSystemCertificates,
                                            chainRawVector);
    } catch (const CryptoLogic::Exception::DecryptDBRowError &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::Base &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
    } catch (const std::exception& e) {
        LogError("STD exception " << e.what());
        retCode = CKM_API_ERROR_SERVER_ERROR;
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
    DB::Row row;
    Crypto::SW::CryptoService cs;
    RawBuffer signature;

    int retCode = CKM_API_SUCCESS;

    try {
        retCode = readDataHelper(false, cred, DataType::DB_KEY_FIRST, privateKeyName, ownerLabel, password, row);
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
    } catch (const CryptoLogic::Exception::DecryptDBRowError &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::Base &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
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
            Crypto::SW::CryptoService cs;
            DB::Row row;
            KeyImpl key;

            // try certificate first - looking for a public key.
            // in case of PKCS, pub key from certificate will be found first
            // rather than private key from the same PKCS.
            retCode = readDataHelper(false, cred, DataType::CERTIFICATE, publicKeyOrCertName, ownerLabel, password, row);
            if (retCode == CKM_API_SUCCESS) {
                CertificateImpl cert(row.data, DataFormat::FORM_DER);
                key = cert.getKeyImpl();
            } else if (retCode == CKM_API_ERROR_DB_ALIAS_UNKNOWN) {
                retCode = readDataHelper(false, cred, DataType::DB_KEY_FIRST, publicKeyOrCertName, ownerLabel, password, row);
                if (retCode != CKM_API_SUCCESS)
                    break;
                key = KeyImpl(row.data);
            } else {
                break;
            }

            if (key.empty()) {
                retCode = CKM_API_ERROR_SERVER_ERROR;
                break;
            }

            retCode = cs.verifySignature(key, message, signature, hash, padding);
        } while(0);
    } catch (const Crypto::SW::CryptoService::Exception::Crypto_internal &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const Crypto::SW::CryptoService::Exception::opensslError &e) {
        LogError("KeyProvider failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const KeyProvider::Exception::Base &e) {
        LogError("KeyProvider failed with error: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const CryptoLogic::Exception::DecryptDBRowError &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_AUTHENTICATION_FAILED;
    } catch (const CryptoLogic::Exception::Base &e) {
        LogError("CryptoLogic failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_SERVER_ERROR;
    } catch (const DB::Crypto::Exception::Base &e) {
        LogError("DB::Crypto failed with message: " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_ERROR;
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
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
        const Credentials &cred,                // who's the client
        const Name &name,
        const Label &label,                     // who's the owner
        const Label &accessorLabel,             // who will get the access
        const PermissionMask permissionMask)
{
    auto &handler = selectDatabase(cred, label);

    // we don't know the client
    if (cred.smackLabel.empty() || !isLabelValid(cred.smackLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    // use client label if not explicitly provided
    const Label& ownerLabel = label.empty() ? cred.smackLabel : label;

    // verify name and label are correct
    if (!isNameValid(name) || !isLabelValid(ownerLabel) || !isLabelValid(accessorLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    // currently we don't support modification of owner's permissions to his own rows
    if (ownerLabel==accessorLabel)
        return CKM_API_ERROR_INPUT_PARAM;

    // system database does not support write/remove permissions
    if ((0 == ownerLabel.compare(LABEL_SYSTEM_DB)) &&
        (permissionMask & Permission::REMOVE))
        return CKM_API_ERROR_INPUT_PARAM;

    // can the client modify permissions to owner's row?
    int retCode = m_accessControl.canModify(cred, ownerLabel);
    if(retCode != CKM_API_SUCCESS)
        return retCode;

    DB::Crypto::Transaction transaction(&handler.database);

    if( !handler.database.isNameLabelPresent(name, ownerLabel) )
        return CKM_API_ERROR_DB_ALIAS_UNKNOWN;

    // removing non-existing permissions: fail
    if(permissionMask == Permission::NONE)
    {
        if(!handler.database.getPermissionRow(name, ownerLabel, accessorLabel))
            return CKM_API_ERROR_INPUT_PARAM;
    }

    // set permissions to the row owned by ownerLabel for accessorLabel
    handler.database.setPermission(name, ownerLabel, accessorLabel, permissionMask);
    transaction.commit();

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::setPermission(
        const Credentials &cred,
        const int command,
        const int msgID,
        const Name &name,
        const Label &label,
        const Label &accessorLabel,
        const PermissionMask permissionMask)
{
    int retCode;
    Try {
        retCode = setPermissionHelper(cred, name, label, accessorLabel, permissionMask);
    } catch (const CKMLogic::Exception::DatabaseLocked &e) {
        LogError("Error " << e.GetMessage());
        retCode = CKM_API_ERROR_DB_LOCKED;
    } Catch (CKM::Exception) {
        LogError("Error in set row!");
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    return MessageBuffer::Serialize(command, msgID, retCode).Pop();
}

} // namespace CKM

