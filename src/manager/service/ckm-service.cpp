/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckm-service.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       CKM service implementation.
 */

#include <protocols.h>

#include <dpl/serialization.h>
#include <dpl/log/log.h>

#include <ckm-service.h>
#include <ckm-logic.h>
#include <initial-value-loader.h>

namespace {
const CKM::InterfaceID SOCKET_ID_CONTROL = 0;
const CKM::InterfaceID SOCKET_ID_STORAGE = 1;
} // namespace anonymous

namespace CKM {

CKMService::CKMService() :
    m_logic(new CKMLogic)
{
    InitialValues::LoadFiles(*m_logic);
}

CKMService::~CKMService()
{
    delete m_logic;
}

void CKMService::Start()
{
    Create();
}

void CKMService::Stop()
{
    Join();
}

GenericSocketService::ServiceDescriptionVector CKMService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_CKM_CONTROL, "http://tizen.org/privilege/keymanager.admin", SOCKET_ID_CONTROL},
        {SERVICE_SOCKET_CKM_STORAGE, "http://tizen.org/privilege/keymanager", SOCKET_ID_STORAGE}
    };
}

void CKMService::SetCommManager(CommMgr *manager)
{
    ThreadService::SetCommManager(manager);
    Register(*manager);
}

// CKMService does not support security check
// so 3rd parameter is not used
bool CKMService::ProcessOne(
    const ConnectionID &conn,
    ConnectionInfo &info,
    bool /*allowed*/)
{
    LogDebug("process One");
    RawBuffer response;

    Try {
        if (!info.buffer.Ready())
            return false;

        if (info.interfaceID == SOCKET_ID_CONTROL)
            response = ProcessControl(info.buffer);
        else
            response = ProcessStorage(info.credentials, info.buffer);

        m_serviceManager->Write(conn, response);

        return true;
    } Catch(MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
    } Catch(Exception::BrokenProtocol) {
        LogError("Broken protocol. Closing socket.");
    } catch (const DataType::Exception::Base &e) {
        LogError("Closing socket. DBDataType::Exception: " << e.DumpToString());
    } catch (const std::string &e) {
        LogError("String exception(" << e << "). Closing socket");
    } catch (const std::exception &e) {
        LogError("Std exception:: " << e.what());
    } catch (...) {
        LogError("Unknown exception. Closing socket.");
    }

    m_serviceManager->Close(conn);
    return false;
}

RawBuffer CKMService::ProcessControl(MessageBuffer &buffer)
{
    int command = 0;
    uid_t user = 0;
    ControlCommand cc;
    Password newPass, oldPass;
    Label smackLabel;

    buffer.Deserialize(command);

    LogDebug("Process control. Command: " << command);

    cc = static_cast<ControlCommand>(command);

    switch (cc) {
    case ControlCommand::UNLOCK_USER_KEY:
        buffer.Deserialize(user, newPass);
        return m_logic->unlockUserKey(user, newPass);
    case ControlCommand::LOCK_USER_KEY:
        buffer.Deserialize(user);
        return m_logic->lockUserKey(user);
    case ControlCommand::REMOVE_USER_DATA:
        buffer.Deserialize(user);
        return m_logic->removeUserData(user);
    case ControlCommand::CHANGE_USER_PASSWORD:
        buffer.Deserialize(user, oldPass, newPass);
        return m_logic->changeUserPassword(user, oldPass, newPass);
    case ControlCommand::RESET_USER_PASSWORD:
        buffer.Deserialize(user, newPass);
        return m_logic->resetUserPassword(user, newPass);
    case ControlCommand::REMOVE_APP_DATA:
        buffer.Deserialize(smackLabel);
        return m_logic->removeApplicationData(smackLabel);
    case ControlCommand::UPDATE_CC_MODE:
        return m_logic->updateCCMode();
    case ControlCommand::SET_PERMISSION:
    {
        Name name;
        Label label;
        Label accessorLabel;
        PermissionMask permissionMask = 0;

        buffer.Deserialize(user, name, label, accessorLabel, permissionMask);

        Credentials cred(user, label);
        return m_logic->setPermission(
            cred,
            command,
            0, // dummy
            name,
            label,
            accessorLabel,
            permissionMask);
    }
    default:
        Throw(Exception::BrokenProtocol);
    }
}

RawBuffer CKMService::ProcessStorage(Credentials &cred, MessageBuffer &buffer)
{
    int command = 0;
    int msgID = 0;
    int tmpDataType = 0;
    Name name;
    Label label, accessorLabel;

    buffer.Deserialize(command);
    buffer.Deserialize(msgID);

    // This is a workaround solution for locktype=None in Tizen 2.2.1
    // When locktype is None, lockscreen app doesn't interfere with unlocking process.
    // Therefor lockscreen app cannot notify unlock events to key-manager when locktype is None.
    // So, to unlock user data when lock type is None, key-manager always try to unlock user data with null password.
    // Even if the result is fail, it will be ignored.
    Password nullPassword("");
    m_logic->unlockUserKey(cred.clientUid, nullPassword);

    LogDebug("Process storage. Command: " << command);

    switch (static_cast<LogicCommand>(command)) {
    case LogicCommand::SAVE:
    {
        RawBuffer rawData;
        PolicySerializable policy;
        buffer.Deserialize(tmpDataType, name, label, rawData, policy);
        return m_logic->saveData(
            cred,
            msgID,
            name,
            label,
            Crypto::Data(DataType(tmpDataType), std::move(rawData)),
            policy);
    }
    case LogicCommand::SAVE_PKCS12:
    {
        RawBuffer rawData;
        PKCS12Serializable pkcs;
        PolicySerializable keyPolicy, certPolicy;
        buffer.Deserialize(name, label, pkcs, keyPolicy, certPolicy);
        return m_logic->savePKCS12(
            cred,
            msgID,
            name,
            label,
            pkcs,
            keyPolicy,
            certPolicy);
    }
    case LogicCommand::REMOVE:
    {
        buffer.Deserialize(name, label);
        return m_logic->removeData(
            cred,
            msgID,
            name,
            label);
    }
    case LogicCommand::GET:
    {
        Password password;
        buffer.Deserialize(tmpDataType, name, label, password);
        return m_logic->getData(
            cred,
            msgID,
            DataType(tmpDataType),
            name,
            label,
            password);
    }
    case LogicCommand::GET_PKCS12:
    {
        Password passKey;
        Password passCert;
        buffer.Deserialize(
            name,
            label,
            passKey,
            passCert);
        return m_logic->getPKCS12(
            cred,
            msgID,
            name,
            label,
            passKey,
            passCert);
    }
    case LogicCommand::GET_LIST:
    {
        buffer.Deserialize(tmpDataType);
        return m_logic->getDataList(
            cred,
            msgID,
            DataType(tmpDataType));
    }
    case LogicCommand::CREATE_KEY_AES:
    {
        int size = 0;
        Name keyName;
        Label keyLabel;
        PolicySerializable policyKey;
        buffer.Deserialize(
            size,
            policyKey,
            keyName,
            keyLabel);
        return m_logic->createKeyAES(
            cred,
            msgID,
            size,
            keyName,
            keyLabel,
            policyKey);
    }
    case LogicCommand::CREATE_KEY_PAIR:
    {
        CryptoAlgorithmSerializable keyGenAlgorithm;
        Name privateKeyName;
        Label privateKeyLabel;
        Name publicKeyName;
        Label publicKeyLabel;
        PolicySerializable policyPrivateKey;
        PolicySerializable policyPublicKey;
        buffer.Deserialize(keyGenAlgorithm,
                           policyPrivateKey,
                           policyPublicKey,
                           privateKeyName,
                           privateKeyLabel,
                           publicKeyName,
                           publicKeyLabel);
        return m_logic->createKeyPair(
            cred,
            msgID,
            keyGenAlgorithm,
            privateKeyName,
            privateKeyLabel,
            publicKeyName,
            publicKeyLabel,
            policyPrivateKey,
            policyPublicKey);
    }
    case LogicCommand::GET_CHAIN_CERT:
    {
        RawBuffer certificate;
        RawBufferVector untrustedVector;
        RawBufferVector trustedVector;
        bool systemCerts = false;
        buffer.Deserialize(certificate, untrustedVector, trustedVector, systemCerts);
        return m_logic->getCertificateChain(
            cred,
            msgID,
            certificate,
            untrustedVector,
            trustedVector,
            systemCerts);
    }
    case LogicCommand::GET_CHAIN_ALIAS:
    {
        RawBuffer certificate;
        LabelNameVector untrustedVector;
        LabelNameVector trustedVector;
        bool systemCerts = false;
        buffer.Deserialize(certificate, untrustedVector, trustedVector, systemCerts);
        return m_logic->getCertificateChain(
            cred,
            msgID,
            certificate,
            untrustedVector,
            trustedVector,
            systemCerts);
    }
    case LogicCommand::CREATE_SIGNATURE:
    {
        Password password;        // password for private_key
        RawBuffer message;

        CryptoAlgorithmSerializable cAlgorithm;
        buffer.Deserialize(name, label, password, message, cAlgorithm);

        return m_logic->createSignature(
              cred,
              msgID,
              name,
              label,
              password,           // password for private_key
              message,
              cAlgorithm);
    }
    case LogicCommand::VERIFY_SIGNATURE:
    {
        Password password;           // password for public_key (optional)
        RawBuffer message;
        RawBuffer signature;
        CryptoAlgorithmSerializable cAlg;

        buffer.Deserialize(name,
                           label,
                           password,
                           message,
                           signature,
                           cAlg);

        return m_logic->verifySignature(
            cred,
            msgID,
            name,
            label,
            password,           // password for public_key (optional)
            message,
            signature,
            cAlg);
    }
    case LogicCommand::SET_PERMISSION:
    {
        PermissionMask permissionMask = 0;
        buffer.Deserialize(name, label, accessorLabel, permissionMask);
        return m_logic->setPermission(
            cred,
            command,
            msgID,
            name,
            label,
            accessorLabel,
            permissionMask);
    }
    default:
        Throw(Exception::BrokenProtocol);
    }
}

void CKMService::ProcessMessage(MsgKeyRequest msg)
{
    Crypto::GObjShPtr key;
    int ret = m_logic->getKeyForService(msg.cred,
                                        msg.name,
                                        msg.label,
                                        msg.password,
                                        key);
    MsgKeyResponse kResp(msg.id, key, ret);
    try {
        if (!m_commMgr->SendMessage(kResp))
            LogError("No listener found"); // can't do much more
    } catch (...) {
        LogError("Uncaught exception in SendMessage. Check listeners.");
    }
}

void CKMService::ProcessMessage(MsgRemoveAppData msg) {
    LogDebug("Call removeApplicationData. pkgId: " << msg.pkgId);
    m_logic->removeApplicationData(msg.pkgId);
}

void CKMService::CustomHandle(const ReadEvent &event)
{
    LogDebug("Read event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);
    while (ProcessOne(event.connectionID, info, true));
}

void CKMService::CustomHandle(const SecurityEvent & /*event*/)
{
    LogError("This should not happend! SecurityEvent was called on CKMService!");
}

} // namespace CKM

