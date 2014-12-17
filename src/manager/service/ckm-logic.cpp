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

void CKMLogic::loadDKEKFile(uid_t user, const Password &password, bool apiReq) {
    auto &handle = m_userDataMap[user];

    FileSystem fs(user);

    auto wrappedDKEKMain = fs.getDKEK();
    auto wrappedDKEKBackup = fs.getDKEKBackup();

    if (wrappedDKEKMain.empty() && wrappedDKEKBackup.empty()) {
        wrappedDKEKMain = KeyProvider::generateDomainKEK(std::to_string(user), password);
        fs.saveDKEK(wrappedDKEKMain);
    }

    chooseDKEKFile(handle, password, wrappedDKEKMain, wrappedDKEKBackup);

    if (!password.empty() || apiReq) {
        handle.isDKEKConfirmed = true;

        if (true == handle.isMainDKEK)
            fs.removeDKEKBackup();
        else
            fs.restoreDKEK();
    }
}

void CKMLogic::chooseDKEKFile(
    UserData &handle,
    const Password &password,
    const RawBuffer &first,
    const RawBuffer &second)
{
    try {
        handle.keyProvider = KeyProvider(first, password);
        handle.isMainDKEK = true;
    } catch (const KeyProvider::Exception::Base &e) {
        if (second.empty())
            throw;
        handle.keyProvider = KeyProvider(second, password);
        handle.isMainDKEK = false;
    }
}

void CKMLogic::saveDKEKFile(uid_t user, const Password &password) {
    auto &handle = m_userDataMap[user];

    FileSystem fs(user);
    if (handle.isMainDKEK)
        fs.saveDKEKBackup(fs.getDKEK());

    fs.saveDKEK(handle.keyProvider.getWrappedDomainKEK(password));

    handle.isMainDKEK = true;
    handle.isDKEKConfirmed = false;
}

RawBuffer CKMLogic::unlockUserKey(uid_t user, const Password &password, bool apiRequest) {
    // TODO try catch for all errors that should be supported by error code
    int retCode = CKM_API_SUCCESS;

    try {
        if (0 == m_userDataMap.count(user) || !(m_userDataMap[user].keyProvider.isInitialized())) {
            auto &handle = m_userDataMap[user];
            FileSystem fs(user);

            loadDKEKFile(user, password, apiRequest);

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
        } else if (apiRequest == true && m_userDataMap[user].isDKEKConfirmed == false) {
            // now we will try to choose the DKEK key and remove old one
            loadDKEKFile(user, password, apiRequest);
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
        loadDKEKFile(user, oldPassword, true);
        saveDKEKFile(user, newPassword);
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
        saveDKEKFile(user, newPassword);
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
    int access_ec = m_accessControl.canSave(ownerLabel, cred.smackLabel);
    if(access_ec != CKM_API_SUCCESS)
    {
        LogWarning("label " << cred.smackLabel << " can not save rows using label " << ownerLabel);
        return access_ec;
    }

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

    return CKM_API_SUCCESS;
}

DBRow CKMLogic::createEncryptedDBRow(
    CryptoLogic &crypto,
    const Name &name,
    const Label &label,
    DBDataType dataType,
    const RawBuffer &data,
    const Policy &policy) const
{
    DBRow row = { name, label, policy.extractable, dataType, DBCMAlgType::NONE,
                  0, RawBuffer(), static_cast<int>(data.size()), data, RawBuffer() };

    // do not encrypt data with password during cc_mode on
    if(m_accessControl.isCCMode()) {
        crypto.encryptRow("", row);
    } else {
        crypto.encryptRow(policy.password, row);
    }
    return row;
}

int CKMLogic::verifyBinaryData(DBDataType dataType, const RawBuffer &input_data) const
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
    DBDataType dataType,
    const PolicySerializable &policy)
{
    int retCode;
    if (0 == m_userDataMap.count(cred.uid))
        retCode = CKM_API_ERROR_DB_LOCKED;
    else
    {
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
        } catch (const DBCrypto::Exception::InternalError &e) {
            LogError("DBCrypto failed with message: " << e.GetMessage());
            retCode = CKM_API_ERROR_DB_ERROR;
        } catch (const DBCrypto::Exception::TransactionError &e) {
            LogError("DBCrypto transaction failed with message " << e.GetMessage());
            retCode = CKM_API_ERROR_DB_ERROR;
        }
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
    DBRowVector &output) const
{
    // private key is mandatory
    if( !pkcs.getKey() )
        return CKM_API_ERROR_INVALID_FORMAT;
    Key* keyPtr = pkcs.getKey().get();
    DBDataType keyType = DBDataType(keyPtr->getType());
    RawBuffer keyData = keyPtr->getDER();
    int retCode = verifyBinaryData(keyType, keyData);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    output.push_back(createEncryptedDBRow(crypto, name, ownerLabel, keyType, keyData, keyPolicy));

    // certificate is mandatory
    if( !pkcs.getCertificate() )
        return CKM_API_ERROR_INVALID_FORMAT;
    RawBuffer certData = pkcs.getCertificate().get()->getDER();
    retCode = verifyBinaryData(DBDataType::CERTIFICATE, certData);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    output.push_back(createEncryptedDBRow(crypto, name, ownerLabel, DBDataType::CERTIFICATE, certData, certPolicy));

    // CA cert chain
    unsigned int cert_index = 0;
    for(const auto & ca : pkcs.getCaCertificateShPtrVector())
    {
        DBDataType chainDataType = DBDataType::getChainDatatype(cert_index ++);
        RawBuffer caCertData = ca->getDER();
        int retCode = verifyBinaryData(chainDataType, caCertData);
        if(retCode != CKM_API_SUCCESS)
            return retCode;

        output.push_back(createEncryptedDBRow(crypto, name, ownerLabel, chainDataType, caCertData, certPolicy));
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
    int retCode;
    if (0 == m_userDataMap.count(cred.uid))
        retCode = CKM_API_ERROR_DB_LOCKED;
    else
    {
        try {
            retCode = saveDataHelper(cred, name, label, pkcs, keyPolicy, certPolicy);
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
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE_PKCS12),
                                             commandId,
                                             retCode);
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
                                             retCode);
    return response.Pop();
}

int CKMLogic::readSingleRow(const Name &name,
                            const Label &ownerLabel,
                            DBDataType dataType,
                            DBCrypto & database,
                            DBRow &row)
{
    DBCrypto::DBRowOptional row_optional;
    if (dataType.isKey())
    {
        // read all key types
        row_optional = database.getDBRow(name,
                                         ownerLabel,
                                         DBDataType::DB_KEY_FIRST,
                                         DBDataType::DB_KEY_LAST);
    } else {
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


int CKMLogic::readMultiRow(const Name &name,
                           const Label &ownerLabel,
                           DBDataType dataType,
                           DBCrypto & database,
                           DBRowVector &output)
{
    if (dataType.isKey())
    {
        // read all key types
        database.getDBRows(name,
                          ownerLabel,
                          DBDataType::DB_KEY_FIRST,
                          DBDataType::DB_KEY_LAST,
                          output);
    }
    else if (dataType.isChainCert())
    {
        // read all key types
        database.getDBRows(name,
                          ownerLabel,
                          DBDataType::DB_CHAIN_FIRST,
                          DBDataType::DB_CHAIN_LAST,
                          output);
    }
    else
    {
        // read anything else
        database.getDBRows(name,
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
    DBRowVector &rows)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

    if (!isNameValid(name) || !isLabelValid(ownerLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    auto &handler = m_userDataMap[cred.uid];

    // read rows
    DBCrypto::Transaction transaction(&handler.database);
    int ec = readMultiRow(name, ownerLabel, dataType, handler.database, rows);
    if(CKM_API_SUCCESS != ec)
        return ec;

    // all read rows belong to the same owner
    DBRow & firstRow = rows.at(0);

    // check access rights
    ec = checkDataPermissionsHelper(name, ownerLabel, cred.smackLabel, firstRow, exportFlag, handler.database);
    if(CKM_API_SUCCESS != ec)
        return ec;

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
    int ec = readSingleRow(name, ownerLabel, dataType, handler.database, row);
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

int CKMLogic::getPKCS12Helper(
    const Credentials &cred,
    const Name &name,
    const Label &label,
    KeyShPtr & privKey,
    CertificateShPtr & cert,
    CertificateShPtrVector & caChain)
{
    int retCode;

    // read private key (mandatory)
    DBRow privKeyRow;
    retCode = readDataHelper(true, cred, DBDataType::DB_KEY_FIRST, name, label, CKM::Password(), privKeyRow);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    privKey = CKM::Key::create(privKeyRow.data);

    // read certificate (mandatory)
    DBRow certRow;
    retCode = readDataHelper(true, cred, DBDataType::CERTIFICATE, name, label, CKM::Password(), certRow);
    if(retCode != CKM_API_SUCCESS)
        return retCode;
    cert = CKM::Certificate::create(certRow.data, DataFormat::FORM_DER);

    // read CA cert chain (optional)
    DBRowVector rawCaChain;
    retCode = readDataHelper(true, cred, DBDataType::DB_CHAIN_FIRST, name, label, CKM::Password(), rawCaChain);
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
        const Label &label)
{
    int retCode;
    PKCS12Serializable output;

    try {
        KeyShPtr privKey;
        CertificateShPtr cert;
        CertificateShPtrVector caChain;
        retCode = getPKCS12Helper(cred, name, label, privKey, cert, caChain);

        // prepare response
        if(retCode == CKM_API_SUCCESS)
            output = PKCS12Serializable(privKey, cert, caChain);

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

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_PKCS12),
                                             commandId,
                                             retCode,
                                             output);
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
            if (dataType.isKey()) {
                // list all key types
                database.listNames(cred.smackLabel,
                                   labelNameVector,
                                   DBDataType::DB_KEY_FIRST,
                                   DBDataType::DB_KEY_LAST);
            } else {
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

int CKMLogic::saveDataHelper(
    const Credentials &cred,
    const Name &name,
    const Label &label,
    DBDataType dataType,
    const RawBuffer &data,
    const PolicySerializable &policy)
{
    auto &handler = m_userDataMap[cred.uid];

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

    // check if save is possible
    DBCrypto::Transaction transaction(&handler.database);
    int retCode = checkSaveConditions(cred, handler, name, ownerLabel);
    if(retCode != CKM_API_SUCCESS)
        return retCode;

    // save the data
    DBRow encryptedRow = createEncryptedDBRow(handler.crypto, name, ownerLabel, dataType, data, policy);
    handler.database.saveDBRow(encryptedRow);

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
    auto &handler = m_userDataMap[cred.uid];

    // use client label if not explicitly provided
    const Label &ownerLabel = label.empty() ? cred.smackLabel : label;

    // check if save is possible
    DBCrypto::Transaction transaction(&handler.database);
    int retCode = checkSaveConditions(cred, handler, name, ownerLabel);
    if(retCode != CKM_API_SUCCESS)
        return retCode;

    // extract and encrypt the data
    DBRowVector encryptedRows;
    retCode = extractPKCS12Data(handler.crypto, name, ownerLabel, pkcs, keyPolicy, certPolicy, encryptedRows);
    if(retCode != CKM_API_SUCCESS)
        return retCode;

    // save the data
    handler.database.saveDBRows(name, ownerLabel, encryptedRows);
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
                             namePrivate,
                             labelPrivate,
                             DBDataType(prv.getType()),
                             prv.getDER(),
                             policyPrivate);
    if (CKM_API_SUCCESS != retCode)
        return retCode;

    retCode = saveDataHelper(cred,
                             namePublic,
                             labelPublic,
                             DBDataType(pub.getType()),
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

        // try to read chain certificates (if present)
        DBRowVector rawCaChain;
        ec = readDataHelper(false, cred, DBDataType::DB_CHAIN_FIRST, i.second, i.first, CKM::Password(), rawCaChain);
        if(ec != CKM_API_SUCCESS &&
           ec != CKM_API_ERROR_DB_ALIAS_UNKNOWN)
            return ec;
        for(auto &rawCaCert : rawCaChain)
            untrustedCertVector.push_back(CertificateImpl(rawCaCert.data, DataFormat::FORM_DER));
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
        LogError("CryptoLogic failed with message: " << e.GetMessage());
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

            // try certificate first - looking for a public key.
            // in case of PKCS, pub key from certificate will be found first
            // rather than private key from the same PKCS.
            retCode = readDataHelper(false, cred, DBDataType::CERTIFICATE, publicKeyOrCertName, ownerLabel, password, row);
            if (retCode == CKM_API_SUCCESS) {
                CertificateImpl cert(row.data, DataFormat::FORM_DER);
                key = cert.getKeyImpl();
            } else if (retCode == CKM_API_ERROR_DB_ALIAS_UNKNOWN) {
                retCode = readDataHelper(false, cred, DBDataType::DB_KEY_FIRST, publicKeyOrCertName, ownerLabel, password, row);
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
        const Permission newPermission)
{
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

    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    auto &database = m_userDataMap[cred.uid].database;
    DBCrypto::Transaction transaction(&database);

    if( ! database.isNameLabelPresent(name, ownerLabel) )
        return CKM_API_ERROR_DB_ALIAS_UNKNOWN;

    // removing non-existing permissions: fail
    if(newPermission == Permission::NONE)
    {
        if( !database.getPermissionRow(name, ownerLabel, accessorLabel) )
            return CKM_API_ERROR_INPUT_PARAM;
    }

    database.setPermission(name, cred.smackLabel, accessorLabel, newPermission);
    transaction.commit();

    return CKM_API_SUCCESS;
}

RawBuffer CKMLogic::setPermission(
        const Credentials &cred,
        int command,
        int msgID,
        const Name &name,
        const Label &label,
        const Label &accessorLabel,
        const Permission newPermission)
{
    int retCode;
    Try {
        retCode = setPermissionHelper(cred, name, label, accessorLabel, newPermission);
    } Catch (CKM::Exception) {
        LogError("Error in set row!");
        retCode = CKM_API_ERROR_DB_ERROR;
    }

    return MessageBuffer::Serialize(command, msgID, retCode).Pop();
}

} // namespace CKM

