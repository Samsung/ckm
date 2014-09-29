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

#include <client-manager-impl.h>
#include <client-common.h>
#include <message-buffer.h>
#include <protocols.h>
#include <key-impl.h>
#include <certificate-impl.h>

namespace {

void clientInitialize(void) {
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
}

} // namespace anonymous

namespace CKM {

bool ManagerImpl::s_isInit = false;

ManagerImpl::ManagerImpl()
  : m_counter(0)
{
    // TODO secure with mutex
    if (!s_isInit) {
        s_isInit = true;
        clientInitialize();
    }

}


int ManagerImpl::saveBinaryData(
    const Alias &alias,
    DBDataType dataType,
    const RawBuffer &rawData,
    const Policy &policy)
{
    m_counter++;

    return try_catch([&] {
        if (alias.empty() || rawData.empty())
            return CKM_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::SAVE));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(dataType));
        Serialization::Serialize(send, alias);
        Serialization::Serialize(send, rawData);
        Serialization::Serialize(send, PolicySerializable(policy));

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
        int opType;
        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        Deserialization::Deserialize(recv, opType);

        if (counter != m_counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int ManagerImpl::saveKey(const Alias &alias, const KeyShPtr &key, const Policy &policy) {
    if (key.get() == NULL)
        return CKM_API_ERROR_INPUT_PARAM;
    return saveBinaryData(alias, toDBDataType(key->getType()), key->getDER(), policy);
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

int ManagerImpl::removeBinaryData(const Alias &alias, DBDataType dataType)
{
    return try_catch([&] {
        if (alias.empty())
            return CKM_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::REMOVE));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(dataType));
        Serialization::Serialize(send, alias);

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
        int opType;
        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        Deserialization::Deserialize(recv, opType);

        if (counter != m_counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int ManagerImpl::removeKey(const Alias &alias) {
    return removeBinaryData(alias, DBDataType::KEY_RSA_PUBLIC);
}

int ManagerImpl::removeCertificate(const Alias &alias) {
    return removeBinaryData(alias, DBDataType::CERTIFICATE);
}

int ManagerImpl::removeData(const Alias &alias) {
    return removeBinaryData(alias, DBDataType::BINARY_DATA);
}

int ManagerImpl::getBinaryData(
    const Alias &alias,
    DBDataType sendDataType,
    const Password &password,
    DBDataType &recvDataType,
    RawBuffer &rawData)
{
    return try_catch([&] {
        if (alias.empty())
            return CKM_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::GET));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(sendDataType));
        Serialization::Serialize(send, alias);
        Serialization::Serialize(send, password);

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
        int tmpDataType;
        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        Deserialization::Deserialize(recv, tmpDataType);
        Deserialization::Deserialize(recv, rawData);
        recvDataType = static_cast<DBDataType>(tmpDataType);

        if (counter != m_counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

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
    DBDataType recvDataType;

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
    return try_catch([&] {

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::GET_LIST));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(dataType));

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
        int tmpDataType;

        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        Deserialization::Deserialize(recv, tmpDataType);
        Deserialization::Deserialize(recv, aliasVector);
        if ((command != static_cast<int>(LogicCommand::GET_LIST)) || (counter != m_counter)) {
            return CKM_API_ERROR_UNKNOWN;
        }

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
    m_counter++;
    int my_counter = m_counter;
    return try_catch([&] {

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(cmd_type));
        Serialization::Serialize(send, my_counter);
        Serialization::Serialize(send, static_cast<int>(additional_param));
        Serialization::Serialize(send, PolicySerializable(policyPrivateKey));
        Serialization::Serialize(send, PolicySerializable(policyPublicKey));
        Serialization::Serialize(send, privateKeyAlias);
        Serialization::Serialize(send, publicKeyAlias);

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;

        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
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
    CertificateShPtrVector &certificateChainVector)
{
    return try_catch([&] {

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(command));
        Serialization::Serialize(send, counter);
        Serialization::Serialize(send, certificate->getDER());
        Serialization::Serialize(send, sendData);
        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int retCommand;
        int retCounter;
        RawBufferVector rawBufferVector;

        Deserialization::Deserialize(recv, retCommand);
        Deserialization::Deserialize(recv, retCounter);
        Deserialization::Deserialize(recv, retCode);
        Deserialization::Deserialize(recv, rawBufferVector);

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
        certificateChainVector);
}

int ManagerImpl::getCertificateChain(
    const CertificateShPtr &certificate,
    const AliasVector &untrustedCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    return getCertChain(
        LogicCommand::GET_CHAIN_ALIAS,
        ++m_counter,
        certificate,
        untrustedCertificates,
        certificateChainVector);
}

int ManagerImpl::createSignature(
    const Alias &privateKeyAlias,
    const Password &password,           // password for private_key
    const RawBuffer &message,
    const HashAlgorithm hash,
    const RSAPaddingAlgorithm padding,
    RawBuffer &signature)
{
    m_counter++;
    int my_counter = m_counter;
    return try_catch([&] {

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::CREATE_SIGNATURE));
        Serialization::Serialize(send, my_counter);
        Serialization::Serialize(send, privateKeyAlias);
        Serialization::Serialize(send, password);
        Serialization::Serialize(send, message);
        Serialization::Serialize(send, static_cast<int>(hash));
        Serialization::Serialize(send, static_cast<int>(padding));

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;

        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        Deserialization::Deserialize(recv, signature);

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
    m_counter++;
    int my_counter = m_counter;
    return try_catch([&] {

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::VERIFY_SIGNATURE));
        Serialization::Serialize(send, my_counter);
        Serialization::Serialize(send, publicKeyOrCertAlias);
        Serialization::Serialize(send, password);
        Serialization::Serialize(send, message);
        Serialization::Serialize(send, signature);
        Serialization::Serialize(send, static_cast<int>(hash));
        Serialization::Serialize(send, static_cast<int>(padding));

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;

        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);

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
        MessageBuffer send, recv;

        RawBufferVector rawCertChain;
        for (auto &e: certChain) {
            rawCertChain.push_back(e->getDER());
        }

        Serialization::Serialize(send, my_counter);
        Serialization::Serialize(send, rawCertChain);

        int retCode = sendToServer(
            SERVICE_SOCKET_OCSP,
            send.Pop(),
            recv);

        if (CKM_API_SUCCESS != retCode) {
            return retCode;
        }

        int counter;

        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        Deserialization::Deserialize(recv, ocspStatus);

        if (my_counter != counter) {
            return CKM_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int ManagerImpl::allowAccess(const std::string &/*alias*/,
                             const std::string &/*accessor*/,
                             AccessRight /*granted*/)
{
    return CKM_API_ERROR_UNKNOWN;
}

int ManagerImpl::denyAccess(const std::string &/*alias*/, const std::string &/*accessor*/)
{
    return CKM_API_ERROR_UNKNOWN;
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

