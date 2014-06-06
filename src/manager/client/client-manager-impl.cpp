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
#include <dpl/serialization.h>

#include <client-manager-impl.h>
#include <client-common.h>
#include <key-impl.h>
#include <message-buffer.h>
#include <protocols.h>

namespace CKM {

int Manager::ManagerImpl::saveBinaryData(
    const Alias &alias,
    DBDataType dataType,
    const RawBuffer &rawData,
    const Policy &policy)
{
    m_counter++;

    return try_catch([&] {
        if (alias.empty() || rawData.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

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

        if (KEY_MANAGER_API_SUCCESS != retCode) {
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
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::saveKey(const Alias &alias, const Key &key, const Policy &policy) {
    return saveBinaryData(alias, toDBDataType(key.getType()), key.getKey(), policy);
}

int Manager::ManagerImpl::saveCertificate(
    const Alias &alias,
    const Certificate &cert,
    const Policy &policy)
{
    return saveBinaryData(alias, DBDataType::CERTIFICATE, cert.getDER(), policy);
}

int Manager::ManagerImpl::saveData(const Alias &alias, const RawBuffer &rawData, const Policy &policy) {
    return saveBinaryData(alias, DBDataType::BINARY_DATA, rawData, policy);
}

int Manager::ManagerImpl::removeBinaryData(const Alias &alias, DBDataType dataType)
{
    return try_catch([&] {
        if (alias.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::REMOVE));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(dataType));
        Serialization::Serialize(send, alias);

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (KEY_MANAGER_API_SUCCESS != retCode) {
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
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::removeKey(const Alias &alias) {
    return removeBinaryData(alias, DBDataType::KEY_RSA_PUBLIC);
}

int Manager::ManagerImpl::removeCertificate(const Alias &alias) {
    return removeBinaryData(alias, DBDataType::CERTIFICATE);
}

int Manager::ManagerImpl::removeData(const Alias &alias) {
    return removeBinaryData(alias, DBDataType::BINARY_DATA);
}

int Manager::ManagerImpl::getBinaryData(
    const Alias &alias,
    DBDataType sendDataType,
    const std::string &password,
    DBDataType &recvDataType,
    RawBuffer &rawData)
{
    return try_catch([&] {
        if (alias.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

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

        if (KEY_MANAGER_API_SUCCESS != retCode) {
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
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::getKey(const Alias &alias, const std::string &password, Key &key) {
    DBDataType recvDataType;
    RawBuffer rawData;

    int retCode = getBinaryData(
        alias,
        DBDataType::KEY_RSA_PUBLIC,
        password,
        recvDataType,
        rawData);

    if (retCode != KEY_MANAGER_API_SUCCESS)
        return retCode;

    Key keyParsed(rawData, toKeyType(recvDataType));

    if (keyParsed.empty())
        return KEY_MANAGER_API_ERROR_BAD_RESPONSE;

    key = keyParsed;

    return KEY_MANAGER_API_SUCCESS;
}

int Manager::ManagerImpl::getCertificate(const Alias &alias, const std::string &password, Certificate &cert)
{
    DBDataType recvDataType;
    RawBuffer rawData;

    int retCode = getBinaryData(
        alias,
        DBDataType::CERTIFICATE,
        password,
        recvDataType,
        rawData);

    if (retCode != KEY_MANAGER_API_SUCCESS)
        return retCode;

    if (recvDataType != DBDataType::CERTIFICATE)
        return KEY_MANAGER_API_ERROR_BAD_RESPONSE;

    Certificate certParsed(rawData, DataFormat::FORM_DER);

    if (certParsed.empty())
        return KEY_MANAGER_API_ERROR_BAD_RESPONSE;

    cert = certParsed;

    return KEY_MANAGER_API_SUCCESS;
}

int Manager::ManagerImpl::getData(const Alias &alias, const std::string &password, RawBuffer &rawData)
{
    DBDataType recvDataType;

    int retCode = getBinaryData(
        alias,
        DBDataType::CERTIFICATE,
        password,
        recvDataType,
        rawData);

    if (retCode != KEY_MANAGER_API_SUCCESS)
        return retCode;

    if (recvDataType != DBDataType::BINARY_DATA)
        return KEY_MANAGER_API_ERROR_BAD_RESPONSE;

    return KEY_MANAGER_API_SUCCESS;
}

int Manager::ManagerImpl::requestBinaryDataAliasVector(DBDataType dataType, AliasVector &aliasVector)
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

        if (KEY_MANAGER_API_SUCCESS != retCode) {
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

        if (counter != m_counter) {
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::requestKeyAliasVector(AliasVector &aliasVector) {
    return requestBinaryDataAliasVector(DBDataType::KEY_RSA_PUBLIC, aliasVector);
}

int Manager::ManagerImpl::requestCertificateAliasVector(AliasVector &aliasVector) {
    return requestBinaryDataAliasVector(DBDataType::CERTIFICATE, aliasVector);
}

int Manager::ManagerImpl::requestDataAliasVector(AliasVector &aliasVector) {
    return requestBinaryDataAliasVector(DBDataType::BINARY_DATA, aliasVector);
}

int Manager::ManagerImpl::createKeyPairRSA(
    const int size,              // size in bits [1024, 2048, 4096]
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey) 
{
    m_counter++;
    int my_counter = m_counter;
    return try_catch([&] {

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::CREATE_KEY_PAIR_RSA));
        Serialization::Serialize(send, my_counter);
        Serialization::Serialize(send, static_cast<int>(size));
        Serialization::Serialize(send, PolicySerializable(policyPrivateKey));
        Serialization::Serialize(send, PolicySerializable(policyPublicKey));
        Serialization::Serialize(send, privateKeyAlias);
        Serialization::Serialize(send, publicKeyAlias);
        
        

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (KEY_MANAGER_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
       

        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        
        if (counter != my_counter) {
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::createKeyPairECDSA(
    ElipticCurve type,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey) 
{
    m_counter++;
    int my_counter = m_counter;
    return try_catch([&] {

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::CREATE_KEY_PAIR_ECDSA));
        Serialization::Serialize(send, my_counter);
        Serialization::Serialize(send, static_cast<unsigned int>(type));
        Serialization::Serialize(send, PolicySerializable(policyPrivateKey));
        Serialization::Serialize(send, PolicySerializable(policyPublicKey));
        Serialization::Serialize(send, privateKeyAlias);
        Serialization::Serialize(send, publicKeyAlias);
        

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (KEY_MANAGER_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;

        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, retCode);
        
        if (counter != my_counter) {
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}
} // namespace CKM

