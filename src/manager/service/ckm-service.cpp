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
 * @file        ckm-service.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#include <service-thread.h>
#include <generic-socket-manager.h>
#include <connection-info.h>
#include <message-buffer.h>
#include <protocols.h>

#include <dpl/serialization.h>
#include <dpl/log/log.h>

#include <ckm-service.h>
#include <ckm-logic.h>

namespace {
const CKM::InterfaceID SOCKET_ID_CONTROL = 0;
const CKM::InterfaceID SOCKET_ID_STORAGE = 1;
} // namespace anonymous

namespace CKM {

CKMService::CKMService()
  : m_logic(new CKMLogic)
{}

CKMService::~CKMService() {
    delete m_logic;
}

GenericSocketService::ServiceDescriptionVector CKMService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_CKM_CONTROL, "ckm::api-control", SOCKET_ID_CONTROL},
        {SERVICE_SOCKET_CKM_STORAGE, "ckm::api-storage", SOCKET_ID_STORAGE}
    };
}

void CKMService::accept(const AcceptEvent &event) {
    LogDebug("Accept event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
    info.credentials = event.credentials;
}

void CKMService::write(const WriteEvent &event) {
    LogDebug("Write event (" << event.size << " bytes)");
}

void CKMService::process(const ReadEvent &event) {
    LogDebug("Read event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);
    while(processOne(event.connectionID, info));
}

bool CKMService::processOne(
    const ConnectionID &conn,
    ConnectionInfo &info)
{
    LogDebug ("process One");
    RawBuffer response;

    Try {
        if (!info.buffer.Ready())
            return false;

        if (info.interfaceID == SOCKET_ID_CONTROL)
            response = processControl(info.buffer);
        else
            response = processStorage(info.credentials, info.buffer);

        m_serviceManager->Write(conn, response);

        return true;
    } Catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
    } catch (const std::string &e) {
        LogError("String exception(" << e << "). Closing socket");
    } catch (...) {
        LogError("Unknown exception. Closing socket.");
    }

    m_serviceManager->Close(conn);
    return false;
}

RawBuffer CKMService::processControl(MessageBuffer &buffer) {
    int command;
    uid_t user;
    ControlCommand cc;
    std::string newPass, oldPass;

    Deserialization::Deserialize(buffer, command);
    Deserialization::Deserialize(buffer, user);

    cc = static_cast<ControlCommand>(command);

    switch(cc) {
    case ControlCommand::UNLOCK_USER_KEY:
        Deserialization::Deserialize(buffer, newPass);
        return m_logic->unlockUserKey(user, newPass);
    case ControlCommand::LOCK_USER_KEY:
        return m_logic->lockUserKey(user);
    case ControlCommand::REMOVE_USER_DATA:
        return m_logic->removeUserData(user);
    case ControlCommand::CHANGE_USER_PASSWORD:
        Deserialization::Deserialize(buffer, oldPass);
        Deserialization::Deserialize(buffer, newPass);
        return m_logic->changeUserPassword(user, oldPass, newPass);
    case ControlCommand::RESET_USER_PASSWORD:
        Deserialization::Deserialize(buffer, newPass);
        return m_logic->resetUserPassword(user, newPass);
    default:
        // TODO
        throw 1; // broken protocol
    }
}

RawBuffer CKMService::processStorage(Credentials &cred, MessageBuffer &buffer){
    int command;
    int commandId;
    int tmpDataType;
    Alias alias;
    std::string user;
    LogicCommand sc;

    Deserialization::Deserialize(buffer, command);
    Deserialization::Deserialize(buffer, commandId);

    sc = static_cast<LogicCommand>(command);

    switch(sc) {
        case LogicCommand::SAVE:
        {
            RawBuffer rawData;
            PolicySerializable policy;
            Deserialization::Deserialize(buffer, tmpDataType);
            Deserialization::Deserialize(buffer, alias);
            Deserialization::Deserialize(buffer, rawData);
            Deserialization::Deserialize(buffer, policy);
            return m_logic->saveData(
                cred,
                commandId,
                static_cast<DBDataType>(tmpDataType),
                alias,
                rawData,
                policy);
        }
        case LogicCommand::REMOVE:
        {
            Deserialization::Deserialize(buffer, tmpDataType);
            Deserialization::Deserialize(buffer, alias);
            return m_logic->removeData(
                cred,
                commandId,
                static_cast<DBDataType>(tmpDataType),
                alias);
        }
        case LogicCommand::GET:
        {
            std::string password;
            Deserialization::Deserialize(buffer, tmpDataType);
            Deserialization::Deserialize(buffer, alias);
            Deserialization::Deserialize(buffer, password);
            return m_logic->getData(
                cred,
                commandId,
                static_cast<DBDataType>(tmpDataType),
                alias,
                password);
        }
        case LogicCommand::GET_LIST:
        {
            Deserialization::Deserialize(buffer, tmpDataType);
            return m_logic->getDataList(
                cred,
                commandId,
                static_cast<DBDataType>(tmpDataType));
        }
        case LogicCommand::CREATE_KEY_PAIR_RSA:
        {
            int size;
            Alias privateKeyAlias;
            Alias publicKeyAlias;
            PolicySerializable policyPrivateKey;
            PolicySerializable policyPublicKey;
            Deserialization::Deserialize(buffer, size);
            Deserialization::Deserialize(buffer, policyPrivateKey);
            Deserialization::Deserialize(buffer, policyPublicKey);
            Deserialization::Deserialize(buffer, privateKeyAlias);
            Deserialization::Deserialize(buffer, publicKeyAlias);
            return m_logic->createKeyPairRSA(
                cred,
                commandId,
                size,
                privateKeyAlias,
                publicKeyAlias,
                policyPrivateKey,
                policyPublicKey);
        }
        case LogicCommand::CREATE_KEY_PAIR_ECDSA:
        {
            unsigned int type;
            Alias privateKeyAlias;
            Alias publicKeyAlias;
            PolicySerializable policyPrivateKey;
            PolicySerializable policyPublicKey;
            Deserialization::Deserialize(buffer, type);
            Deserialization::Deserialize(buffer, policyPrivateKey);
            Deserialization::Deserialize(buffer, policyPublicKey);
            Deserialization::Deserialize(buffer, privateKeyAlias);
            Deserialization::Deserialize(buffer, publicKeyAlias);
            return m_logic->createKeyPairECDSA(
                cred,
                commandId,
                type,
                privateKeyAlias,
                publicKeyAlias,
                policyPrivateKey,
                policyPublicKey);
        }
        default:
        // TODO
            throw 1; // broken protocol
    }
}


void CKMService::close(const CloseEvent &event) {
    LogDebug("Close event");
    m_connectionInfoMap.erase(event.connectionID.counter);
}

} // namespace CKM

