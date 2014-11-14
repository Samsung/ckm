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
 */
/*
 * @file       receiver.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <storage-receiver.h>
#include <protocols.h>
#include <dpl/log/log.h>
#include <key-impl.h>
#include <certificate-impl.h>
#include <client-common.h>

namespace CKM {

namespace {

enum class DataType {
    KEY,
    CERT,
    DATA
};

DataType type(int dbDataType)
{
    switch(static_cast<DBDataType>(dbDataType))
    {
    case DBDataType::KEY_RSA_PUBLIC:
    case DBDataType::KEY_RSA_PRIVATE:
    case DBDataType::KEY_ECDSA_PUBLIC:
    case DBDataType::KEY_ECDSA_PRIVATE:
    case DBDataType::KEY_DSA_PUBLIC:
    case DBDataType::KEY_DSA_PRIVATE:
    case DBDataType::KEY_AES:
        return DataType::KEY;

    case DBDataType::CERTIFICATE:
        return DataType::CERT;

    case DBDataType::BINARY_DATA:
        return DataType::DATA;

    default:
        LogError("Unsupported data type: " <<dbDataType);
        ThrowMsg(IReceiver::BadResponse, "Unsupported data type: " << dbDataType);
    }
}

} // namespace anonymous

StorageReceiver::StorageReceiver(MessageBuffer& buffer, AsyncRequest::Map& requests) :
    m_buffer(buffer),
    m_requests(requests),
    m_observer(NULL)
{
}

void StorageReceiver::parseResponse()
{
    int command = 0, id = 0;
    m_buffer.Deserialize(command, id);

    auto it = m_requests.find(id);
    if (it == m_requests.end()) {
        LogError("Request with id " << id << " not found!");
        ThrowMsg(BadResponse, "Request with id " << id << " not found!");
    }

    // let it throw
    AsyncRequest req = std::move(m_requests.at(id));
    m_requests.erase(id);

    m_observer = req.observer;

    switch (static_cast<LogicCommand>(command)) {
    case LogicCommand::GET:
        parseGetCommand();
        break ;
    case LogicCommand::GET_LIST:
        parseGetListCommand();
        break;
    case LogicCommand::SAVE:
        parseSaveCommand();
        break;
    case LogicCommand::REMOVE:
        parseRemoveCommand();
        break;
    case LogicCommand::CREATE_KEY_PAIR_RSA:
        parseRetCode(&ManagerAsync::Observer::ReceivedCreateKeyPairRSA);
        break;
    case LogicCommand::CREATE_KEY_PAIR_ECDSA:
        parseRetCode(&ManagerAsync::Observer::ReceivedCreateKeyPairECDSA);
        break;
    case LogicCommand::GET_CHAIN_CERT:
    case LogicCommand::GET_CHAIN_ALIAS:
        parseGetChainCertCommand();
        break;
    case LogicCommand::CREATE_SIGNATURE:
        parseCreateSignatureCommand();
        break;
    case LogicCommand::VERIFY_SIGNATURE:
        parseRetCode(&ManagerAsync::Observer::ReceivedVerifySignature);
        break;
    case LogicCommand::CREATE_KEY_PAIR_DSA:
        parseRetCode(&ManagerAsync::Observer::ReceivedCreateKeyPairDSA);
        break;
    case LogicCommand::SET_PERMISSION:
        parseRetCode(&ManagerAsync::Observer::ReceivedSetPermission);
        break;

    default:
        LogError("Unknown command id: " << command);
        ThrowMsg(BadResponse, "Unknown command id: " << command);
        break;
    }
}

void StorageReceiver::parseGetCommand()
{
    RawBuffer rawData;
    int dataType = 0, retCode = 0;
    m_buffer.Deserialize(retCode, dataType, rawData);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    switch(type(dataType))
    {
    case DataType::KEY:
        m_observer->ReceivedKey(KeyImpl(rawData));
        break;
    case DataType::CERT:
        m_observer->ReceivedCertificate(CertificateImpl(rawData, DataFormat::FORM_DER));
        break;
    case DataType::DATA:
        m_observer->ReceivedData(std::move(rawData));
        break;
    }
}

void StorageReceiver::parseGetListCommand()
{
    int dataType = 0, retCode = 0;
    LabelNameVector labelNameVector;
    m_buffer.Deserialize(retCode, dataType, labelNameVector);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    AliasVector aliasVector;
    for(const auto &it : labelNameVector)
        aliasVector.push_back( AliasSupport::merge(it.first, it.second) );

    switch(type(dataType))
    {
    case DataType::KEY:
        m_observer->ReceivedKeyAliasVector(std::move(aliasVector));
        break;
    case DataType::CERT:
        m_observer->ReceivedCertificateAliasVector(std::move(aliasVector));
        break;
    case DataType::DATA:
        m_observer->ReceivedDataAliasVector(std::move(aliasVector));
        break;
    }
}

void StorageReceiver::parseSaveCommand()
{
    int dataType = 0, retCode = 0;
    m_buffer.Deserialize(retCode, dataType);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    switch(type(dataType))
    {
    case DataType::KEY:
        m_observer->ReceivedSaveKey();
        break;
    case DataType::CERT:
        m_observer->ReceivedSaveCertificate();
        break;
    case DataType::DATA:
        m_observer->ReceivedSaveData();
        break;
    }
}

void StorageReceiver::parseRemoveCommand()
{
    int retCode = 0;
    m_buffer.Deserialize(retCode);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    m_observer->ReceivedRemovedAlias();
}

void StorageReceiver::parseGetChainCertCommand()
{
    CertificateShPtrVector certificateChainVector;
    RawBufferVector rawBufferVector;
    int retCode = 0;
    m_buffer.Deserialize(retCode, rawBufferVector);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    for (auto &e: rawBufferVector) {
        CertificateShPtr cert(new CertificateImpl(e, DataFormat::FORM_DER));
        if (cert->empty()) {
            m_observer->ReceivedError(CKM_API_ERROR_BAD_RESPONSE);
            return;
        }
        certificateChainVector.push_back(cert);
    }
    m_observer->ReceivedGetCertificateChain(std::move(certificateChainVector));
}

void StorageReceiver::parseCreateSignatureCommand()
{
    int retCode = 0;
    RawBuffer signature;
    m_buffer.Deserialize(retCode, signature);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    m_observer->ReceivedCreateSignature(std::move(signature));
}

void StorageReceiver::parseSetPermission()
{
    int retCode;
    m_buffer.Deserialize(retCode);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    m_observer->ReceivedSetPermission();
}

void StorageReceiver::parseRetCode(ObserverCb callback)
{
    int retCode = 0;
    m_buffer.Deserialize(retCode);

    // check error code
    if (retCode != CKM_API_SUCCESS) {
         m_observer->ReceivedError(retCode);
         return;
    }

    (m_observer.get()->*callback)();
}

} /* namespace CKM */
