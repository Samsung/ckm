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

#ifndef VCONFKEY_SECURITY_MDPP_STATE
#define VCONFKEY_SECURITY_MDPP_STATE = "file/security_mdpp/security_mdpp_state";
#endif

namespace {
const char * const CERT_SYSTEM_DIR = "/etc/ssl/certs";

const char* const MDPP_MODE_ENFORCING = "Enforcing";
const char* const MDPP_MODE_ENABLED = "Enabled";
const char* const MDPP_MODE_DISABLED = "Disabled";

} // anonymous namespace

namespace CKM {

CKMLogic::CKMLogic() : m_ccMode(false)
{
    if (CKM_API_SUCCESS != m_certStore.setSystemCertificateDir(CERT_SYSTEM_DIR)) {
        LogError("Fatal error in CertificateStore::setSystemCertificateDir. Chain creation will not work");
    }

    updateCCMode_internal();
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

    return MessageBuffer::Serialize(retCode).Pop();
}

void CKMLogic::updateCCMode_internal() {
    int fipsModeStatus = 0;
    int rc = 0;
    bool newMode;

    char *mdppState = vconf_get_str(VCONFKEY_SECURITY_MDPP_STATE);
    newMode = (mdppState && (  !strcmp(mdppState, MDPP_MODE_ENABLED)
                            || !strcmp(mdppState, MDPP_MODE_ENFORCING)
                            || !strcmp(mdppState, MDPP_MODE_DISABLED)));
    if (newMode == m_ccMode)
        return;

    m_ccMode = newMode;

    fipsModeStatus = FIPS_mode();

    if(m_ccMode) {
        if(fipsModeStatus == 0) { // If FIPS mode off
            rc = FIPS_mode_set(1); // Change FIPS_mode from off to on
            if(rc == 0) {
                LogError("Error in FIPS_mode_set function");
            }
        }
    } else {
        if(fipsModeStatus == 1) { // If FIPS mode on
            rc = FIPS_mode_set(0); // Change FIPS_mode from on to off
            if(rc == 0) {
                LogError("Error in FIPS_mode_set function");
            }
        }
    }
}

RawBuffer CKMLogic::updateCCMode() {
    updateCCMode_internal();
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
    Credentials &cred,
    DBDataType dataType,
    const Name &name,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    // proceed to data save
    DBRow row = { name, cred.smackLabel,
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
    if(m_ccMode) {
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
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Name &name,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    int retCode = CKM_API_SUCCESS;
    try {
        verifyBinaryData(dataType, key);

        retCode = saveDataHelper(cred, dataType, name, key, policy);
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
    } catch (const DBCrypto::Exception::NameExists &e) {
        LogError("DBCrypto couldn't save duplicate name");
        retCode = CKM_API_ERROR_DB_ALIAS_EXISTS;
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

RawBuffer CKMLogic::removeData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Name &name,
    const Label &label)
{
    int retCode = CKM_API_SUCCESS;

    if (0 < m_userDataMap.count(cred.uid)) {
        Try {
            // use client label if not explicitly provided
            const Label & ownerLabel = label.empty() ? cred.smackLabel : label;

            // verify name and label are correct
            if (true == checkNameAndLabelValid(name, ownerLabel))
            {
                auto erased = m_userDataMap[cred.uid].database.deleteDBRow(name, ownerLabel, cred.smackLabel);
                // check if the data existed or not
                if(!erased) {
                    LogError("No row for given name and label");
                    retCode = CKM_API_ERROR_DB_ALIAS_UNKNOWN;
                }
            }
            else
            {
                LogError("Invalid label or name format");
                retCode = CKM_API_ERROR_INPUT_PARAM;
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

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::REMOVE),
                                             commandId,
                                             retCode,
                                             static_cast<int>(dataType));
    return response.Pop();
}

bool CKMLogic::checkNameAndLabelValid(const Name &name, const Label &label)
{
    // verify the name is valid
    if(name.find(':') != Label::npos)
        return false;

    // verify the label is valid
    if(label.find(LABEL_NAME_SEPARATOR) != Label::npos)
        return false;

    return true;
}

int CKMLogic::getDataHelper(
    Credentials &cred,
    DBDataType dataType,
    const Name &name,
    const Label &label,
    const Password &password,
    DBRow &row)
{
    if (0 == m_userDataMap.count(cred.uid))
        return CKM_API_ERROR_DB_LOCKED;

    auto &handler = m_userDataMap[cred.uid];

    // use client label if not explicitly provided
    const Label ownerLabel = label.empty() ? cred.smackLabel : label;

    // verify name and label are correct
    if (true != checkNameAndLabelValid(name, ownerLabel))
        return CKM_API_ERROR_INPUT_PARAM;

    DBCrypto::DBRowOptional row_optional;
    if (dataType == DBDataType::CERTIFICATE || dataType == DBDataType::BINARY_DATA)
    {
        row_optional = handler.database.getDBRow(name, ownerLabel, cred.smackLabel, dataType);
    }
    else if ((static_cast<int>(dataType) >= static_cast<int>(DBDataType::DB_KEY_FIRST)) &&
             (static_cast<int>(dataType) <= static_cast<int>(DBDataType::DB_KEY_LAST)))
    {
        row_optional = handler.database.getKeyDBRow(name, ownerLabel, cred.smackLabel);
    }
    else
    {
        LogError("Unknown type of requested data" << (int)dataType);
        return CKM_API_ERROR_BAD_REQUEST;
    }
    if(!row_optional) {
        LogError("No row for given name, label and type");
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
    const Name &name,
    const Label &label,
    const Password &password)
{
    int retCode = CKM_API_SUCCESS;
    DBRow row;

    try {
        retCode = getDataHelper(cred, dataType, name, label, password, row);
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
    if((m_ccMode) && (row.dataType == DBDataType::KEY_RSA_PRIVATE ||
                      row.dataType == DBDataType::KEY_ECDSA_PRIVATE ||
                      row.dataType == DBDataType::KEY_DSA_PRIVATE))
    {
        row.data.clear();
        retCode = CKM_API_ERROR_BAD_REQUEST;
    }

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET),
                                             commandId,
                                             retCode,
                                             static_cast<int>(row.dataType),
                                             row.data);
    return response.Pop();
}

RawBuffer CKMLogic::getDataList(
    Credentials &cred,
    int commandId,
    DBDataType dataType)
{
    int retCode = CKM_API_SUCCESS;
    LabelNameVector labelNameVector;

    if (0 < m_userDataMap.count(cred.uid)) {
        auto &handler = m_userDataMap[cred.uid];
        Try {
            if (dataType == DBDataType::CERTIFICATE || dataType == DBDataType::BINARY_DATA) {
                handler.database.getNames(cred.smackLabel, dataType, labelNameVector);
            } else {
                handler.database.getKeyNames(cred.smackLabel, labelNameVector);
            }
        } Catch (CKM::Exception) {
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
    Credentials &cred,
    const KeyType key_type,
    const int additional_param,
    const Name &namePrivate,
    const Name &namePublic,
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
                            namePrivate,
                            prv.getDER(),
                            policyPrivate);

    if (CKM_API_SUCCESS != retCode)
        return retCode;

    retCode = saveDataHelper(cred,
                            toDBDataType(pub.getType()),
                            namePublic,
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
    const Name &namePrivate,
    const Name &namePublic,
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
                        namePublic,
                        policyPrivate,
                        policyPublic);

    } catch (DBCrypto::Exception::NameExists &e) {
        LogDebug("DBCrypto error: name exists: " << e.GetMessage());
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

    return MessageBuffer::Serialize(static_cast<int>(protocol_cmd), commandId, retCode).Pop();
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

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_CHAIN_CERT),
                                             commandId,
                                             retCode,
                                             chainRawVector);
    return response.Pop();
}

RawBuffer CKMLogic::getCertificateChain(
    Credentials &cred,
    int commandId,
    const RawBuffer &certificate,
    const LabelNameVector &labelNameVector)
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

        for (auto &i: labelNameVector) {
            retCode = getDataHelper(cred, DBDataType::CERTIFICATE, i.second, i.first, Password(), row);

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
    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_CHAIN_ALIAS),
                                             commandId,
                                             retCode,
                                             chainRawVector);
    return response.Pop();
}

RawBuffer CKMLogic::createSignature(
        Credentials &cred,
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
        do {
            retCode = getDataHelper(cred, DBDataType::DB_KEY_FIRST, privateKeyName, ownerLabel, password, row);
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

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::CREATE_SIGNATURE),
                                             commandId,
                                             retCode,
                                             signature);
    return response.Pop();
}

RawBuffer CKMLogic::verifySignature(
        Credentials &cred,
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

            retCode = getDataHelper(cred, DBDataType::DB_KEY_FIRST, publicKeyOrCertName, ownerLabel, password, row);

            if (retCode == CKM_API_SUCCESS) {
                key = KeyImpl(row.data);
            } else if (retCode == CKM_API_ERROR_DB_ALIAS_UNKNOWN) {
                retCode = getDataHelper(cred, DBDataType::CERTIFICATE, publicKeyOrCertName, ownerLabel, password, row);
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

    auto response = MessageBuffer::Serialize(static_cast<int>(LogicCommand::VERIFY_SIGNATURE),
                                             commandId,
                                             retCode);
    return response.Pop();
}

RawBuffer CKMLogic::allowAccess(
        Credentials &cred,
        int command,
        int msgID,
        const Name &name,
        const Label &accessorLabel,
        const AccessRight reqRights)
{
    int retCode = CKM_API_ERROR_VERIFICATION_FAILED;

    if (cred.smackLabel.empty()) {
        retCode = CKM_API_ERROR_INPUT_PARAM;
    } else if (0 < m_userDataMap.count(cred.uid) && !cred.smackLabel.empty()) {
        Try {
            retCode = m_userDataMap[cred.uid].database.setAccessRights(
                name,
                cred.smackLabel,
                accessorLabel,
                reqRights);
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

    return MessageBuffer::Serialize(command, msgID, retCode).Pop();
}

RawBuffer CKMLogic::denyAccess(
        Credentials &cred,
        int command,
        int msgID,
        const Name &name,
        const Label &accessorLabel)
{
    int retCode = CKM_API_ERROR_VERIFICATION_FAILED;

    if (cred.smackLabel.empty()) {
        retCode = CKM_API_ERROR_INPUT_PARAM;
    } else if (0 < m_userDataMap.count(cred.uid)) {
        Try {
            retCode = m_userDataMap[cred.uid].database.clearAccessRights(name, cred.smackLabel, accessorLabel);
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

    return MessageBuffer::Serialize(command, msgID, retCode).Pop();
}

} // namespace CKM

