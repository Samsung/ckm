/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        client-manager-impl.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Manager implementation.
 */
#include <openssl/evp.h>

#include <dpl/serialization.h>
#include <dpl/log/log.h>

#include <crypto.h>
#include <client-manager-impl.h>
#include <client-common.h>
#include <message-buffer.h>
#include <protocols.h>
#include <key-impl.h>
#include <certificate-impl.h>

namespace CKM {

ManagerImpl::ManagerImpl()
  : m_counter(0), m_storageConnection(SERVICE_SOCKET_CKM_STORAGE), m_ocspConnection(SERVICE_SOCKET_OCSP)
{
    initCryptoLib();
}


int ManagerImpl::saveBinaryData(
    const Alias &alias,
    DBDataType dataType,
    const RawBuffer &rawData,
    const Policy &policy)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        if (alias.empty() || rawData.empty())
            return CKM_API_ERROR_INPUT_PARAM;

        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE),
                                             my_counter,
                                             static_cast<int>(dataType),
                                             helper.getName(),
                                             helper.getLabel(),
                                             rawData,
                                             PolicySerializable(policy));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        int opType;
        recv.Deserialize(command, counter, retCode, opType);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int ManagerImpl::saveKey(const Alias &alias, const KeyShPtr &key, const Policy &policy) {
    if (key.get() == NULL)
        return CKM_API_ERROR_INPUT_PARAM;
    Try {
        return saveBinaryData(alias, DBDataType(key->getType()), key->getDER(), policy);
    } Catch (DBDataType::Exception::Base) {
        LogError("Error in key conversion. Could not convert KeyType::NONE to DBDataType!");
    }
    return CKM_API_ERROR_INPUT_PARAM;
}

int ManagerImpl::saveCertificate(
    const Alias &alias,
    const CertificateShPtr &cert,
    const Policy &policy)
{
    if (cert.get() == NULL)
        return CKM_API_ERROR_INPUT_PARAM;
    return saveBinaryData(alias, DBDataType::CERTIFICATE, cert->getDER(), policy);
}

int ManagerImpl::saveData(const Alias &alias, const RawBuffer &rawData, const Policy &policy) {
    if (!policy.extractable)
        return CKM_API_ERROR_INPUT_PARAM;
    return saveBinaryData(alias, DBDataType::BINARY_DATA, rawData, policy);
}


int ManagerImpl::savePKCS12(
    const Alias & alias,
    const PKCS12ShPtr &pkcs,
    const Policy &keyPolicy,
    const Policy &certPolicy)
{
    if (alias.empty() || pkcs.get()==NULL)
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE_PKCS12),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             PKCS12Serializable(*pkcs.get()),
                                             PolicySerializable(keyPolicy),
                                             PolicySerializable(certPolicy));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int ManagerImpl::getPKCS12(const Alias &alias, PKCS12ShPtr &pkcs)
{
    if (alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_PKCS12),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel());

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        PKCS12Serializable gotPkcs;
        recv.Deserialize(command, counter, retCode, gotPkcs);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        pkcs = std::make_shared<PKCS12Impl>(std::move(gotPkcs));

        return retCode;
    });
}


int ManagerImpl::removeAlias(const Alias &alias)
{
    if (alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::REMOVE),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel());

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int ManagerImpl::getBinaryData(
    const Alias &alias,
    DBDataType sendDataType,
    const Password &password,
    DBDataType &recvDataType,
    RawBuffer &rawData)
{
    if (alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;

    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET),
                                             my_counter,
                                             static_cast<int>(sendDataType),
                                             helper.getName(),
                                             helper.getLabel(),
                                             password);

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        int tmpDataType;
        recv.Deserialize(command, counter, retCode, tmpDataType, rawData);
        recvDataType = DBDataType(tmpDataType);

        if (counter != my_counter)
            return CKM_API_ERROR_UNKNOWN;

        return retCode;
    });
}

int ManagerImpl::getKey(const Alias &alias, const Password &password, KeyShPtr &key) {
    DBDataType recvDataType;
    RawBuffer rawData;

    int retCode = getBinaryData(
        alias,
        DBDataType::KEY_RSA_PUBLIC,
        password,
        recvDataType,
        rawData);

    if (retCode != CKM_API_SUCCESS)
        return retCode;

    KeyShPtr keyParsed(new KeyImpl(rawData));

    if (keyParsed->empty()) {
        LogDebug("Key empty - failed to parse!");
        return CKM_API_ERROR_BAD_RESPONSE;
    }

    key = keyParsed;

    return CKM_API_SUCCESS;
}

int ManagerImpl::getCertificate(const Alias &alias, const Password &password, CertificateShPtr &cert)
{
    DBDataType recvDataType;
    RawBuffer rawData;

    int retCode = getBinaryData(
        alias,
        DBDataType::CERTIFICATE,
        password,
        recvDataType,
        rawData);

    if (retCode != CKM_API_SUCCESS)
        return retCode;

    if (recvDataType != DBDataType::CERTIFICATE)
        return CKM_API_ERROR_BAD_RESPONSE;

    CertificateShPtr certParsed(new CertificateImpl(rawData, DataFormat::FORM_DER));

    if (certParsed->empty())
        return CKM_API_ERROR_BAD_RESPONSE;

    cert = certParsed;

    return CKM_API_SUCCESS;
}

int ManagerImpl::getData(const Alias &alias, const Password &password, RawBuffer &rawData)
{
    DBDataType recvDataType = DBDataType::BINARY_DATA;

    int retCode = getBinaryData(
        alias,
        DBDataType::BINARY_DATA,
        password,
        recvDataType,
        rawData);

    if (retCode != CKM_API_SUCCESS)
        return retCode;

    if (recvDataType != DBDataType::BINARY_DATA)
        return CKM_API_ERROR_BAD_RESPONSE;

    return CKM_API_SUCCESS;
}

int ManagerImpl::getBinaryDataAliasVector(DBDataType dataType, AliasVector &aliasVector)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::GET_LIST),
                                             my_counter,
                                             static_cast<int>(dataType));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        int tmpDataType;
        LabelNameVector labelNameVector;
        recv.Deserialize(command, counter, retCode, tmpDataType, labelNameVector);
        if ((command != static_cast<int>(LogicCommand::GET_LIST)) || (counter != my_counter)) {
            return CKM_API_ERROR_UNKNOWN;
        }

        for(const auto &it : labelNameVector)
            aliasVector.push_back( AliasSupport::merge(it.first, it.second) );

        return retCode;
    });
}

int ManagerImpl::getKeyAliasVector(AliasVector &aliasVector) {
    // in fact datatype has no meaning here - if not certificate or binary data
    // then manager decides to list all between DB_KEY_FIRST and DB_KEY_LAST
    return getBinaryDataAliasVector(DBDataType::DB_KEY_LAST, aliasVector);
}

int ManagerImpl::getCertificateAliasVector(AliasVector &aliasVector) {
    return getBinaryDataAliasVector(DBDataType::CERTIFICATE, aliasVector);
}

int ManagerImpl::getDataAliasVector(AliasVector &aliasVector) {
    return getBinaryDataAliasVector(DBDataType::BINARY_DATA, aliasVector);
}

int ManagerImpl::createKeyPairRSA(
    const int size,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return this->createKeyPair(CKM::KeyType::KEY_RSA_PUBLIC, size, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int ManagerImpl::createKeyPairDSA(
    const int size,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return this->createKeyPair(CKM::KeyType::KEY_DSA_PUBLIC, size, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int ManagerImpl::createKeyPairECDSA(
    ElipticCurve type,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return this->createKeyPair(CKM::KeyType::KEY_ECDSA_PUBLIC, static_cast<int>(type), privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int ManagerImpl::createKeyPair(
    const KeyType key_type,
    const int     additional_param,
    const Alias  &privateKeyAlias,
    const Alias  &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    // input type check
    LogicCommand cmd_type;
    switch(key_type)
    {
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_RSA_PRIVATE:
            cmd_type = LogicCommand::CREATE_KEY_PAIR_RSA;
            break;

        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_DSA_PRIVATE:
            cmd_type = LogicCommand::CREATE_KEY_PAIR_DSA;
            break;

        case KeyType::KEY_ECDSA_PUBLIC:
        case KeyType::KEY_ECDSA_PRIVATE:
            cmd_type = LogicCommand::CREATE_KEY_PAIR_ECDSA;
            break;

        default:
            return CKM_API_ERROR_INPUT_PARAM;
    }

    // proceed with sending request
    int my_counter = ++m_counter;

    return try_catch([&] {

        MessageBuffer recv;
        AliasSupport privateHelper(privateKeyAlias);
        AliasSupport publicHelper(publicKeyAlias);
        auto send = MessageBuffer::Serialize(static_cast<int>(cmd_type),
                                             my_counter,
                                             static_cast<int>(additional_param),
                                             PolicySerializable(policyPrivateKey),
                                             PolicySerializable(policyPublicKey),
                                             privateHelper.getName(),
                                             privateHelper.getLabel(),
                                             publicHelper.getName(),
                                             publicHelper.getLabel());

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);
        if (counter != my_counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}


template <class T>
int getCertChain(
    LogicCommand command,
    int counter,
    const CertificateShPtr &certificate,
    const T &sendData,
    CertificateShPtrVector &certificateChainVector,
    ServiceConnection & service_connection)
{
    return try_catch([&] {

        MessageBuffer recv;
        auto send = MessageBuffer::Serialize(static_cast<int>(command),
                                             counter,
                                             certificate->getDER(),
                                             sendData);

        int retCode = service_connection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int retCommand;
        int retCounter;
        RawBufferVector rawBufferVector;
        recv.Deserialize(retCommand, retCounter, retCode, rawBufferVector);

        if ((counter != retCounter) || (static_cast<int>(command) != retCommand)) {
            return CKM_API_ERROR_UNKNOWN;
        }

        if (retCode != CKM_API_SUCCESS) {
            return retCode;
        }

        for (auto &e: rawBufferVector) {
            CertificateShPtr cert(new CertificateImpl(e, DataFormat::FORM_DER));
            if (cert->empty())
                return CKM_API_ERROR_BAD_RESPONSE;
            certificateChainVector.push_back(cert);
        }

        return retCode;
    });
}


int ManagerImpl::getCertificateChain(
    const CertificateShPtr &certificate,
    const CertificateShPtrVector &untrustedCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    RawBufferVector rawBufferVector;

    for (auto &e: untrustedCertificates) {
        rawBufferVector.push_back(e->getDER());
    }

    return getCertChain(
        LogicCommand::GET_CHAIN_CERT,
        ++m_counter,
        certificate,
        rawBufferVector,
        certificateChainVector,
        m_storageConnection);
}

int ManagerImpl::getCertificateChain(
    const CertificateShPtr &certificate,
    const AliasVector &untrustedCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    LabelNameVector untrusted_certs;
    for (auto &e: untrustedCertificates) {
        AliasSupport helper(e);
        untrusted_certs.push_back(std::make_pair(helper.getLabel(), helper.getName()));
    }

    return getCertChain(
        LogicCommand::GET_CHAIN_ALIAS,
        ++m_counter,
        certificate,
        untrusted_certs,
        certificateChainVector,
        m_storageConnection);
}

int ManagerImpl::createSignature(
    const Alias &privateKeyAlias,
    const Password &password,           // password for private_key
    const RawBuffer &message,
    const HashAlgorithm hash,
    const RSAPaddingAlgorithm padding,
    RawBuffer &signature)
{
    int my_counter = ++m_counter;

    return try_catch([&] {

        MessageBuffer recv;
        AliasSupport helper(privateKeyAlias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::CREATE_SIGNATURE),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             password,
                                             message,
                                             static_cast<int>(hash),
                                             static_cast<int>(padding));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode, signature);

        if ((command != static_cast<int>(LogicCommand::CREATE_SIGNATURE))
            || (counter != my_counter))
        {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int ManagerImpl::verifySignature(
    const Alias &publicKeyOrCertAlias,
    const Password &password,           // password for public_key (optional)
    const RawBuffer &message,
    const RawBuffer &signature,
    const HashAlgorithm hash,
    const RSAPaddingAlgorithm padding)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(publicKeyOrCertAlias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::VERIFY_SIGNATURE),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             password,
                                             message,
                                             signature,
                                             static_cast<int>(hash),
                                             static_cast<int>(padding));

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if ((command != static_cast<int>(LogicCommand::VERIFY_SIGNATURE))
            || (counter != my_counter))
        {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int ManagerImpl::ocspCheck(const CertificateShPtrVector &certChain, int &ocspStatus)
{
    return try_catch([&] {
        int my_counter = ++m_counter;
        MessageBuffer recv;

        RawBufferVector rawCertChain;
        for (auto &e: certChain) {
            rawCertChain.push_back(e->getDER());
        }

        auto send = MessageBuffer::Serialize(my_counter, rawCertChain);

        int retCode = m_ocspConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int counter;
        recv.Deserialize(counter, retCode, ocspStatus);

        if (my_counter != counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int ManagerImpl::setPermission(const Alias &alias,
                               const Label &accessor,
                               PermissionMask permissionMask)
{
    int my_counter = ++m_counter;

    return try_catch([&] {
        MessageBuffer recv;
        AliasSupport helper(alias);
        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SET_PERMISSION),
                                             my_counter,
                                             helper.getName(),
                                             helper.getLabel(),
                                             accessor,
                                             permissionMask);

        int retCode = m_storageConnection.processRequest(send.Pop(), recv);
        if (CKM_API_SUCCESS != retCode)
            return retCode;

        int command;
        int counter;
        recv.Deserialize(command, counter, retCode);

        if (my_counter != counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

ManagerShPtr Manager::create() {
    try {
        return std::make_shared<ManagerImpl>();
    } catch (const std::bad_alloc &) {
        LogDebug("Bad alloc was caught during ManagerImpl creation.");
    } catch (...) {
        LogError("Critical error: Unknown exception was caught during ManagerImpl creation!");
    }
    return ManagerShPtr();
}

} // namespace CKM
