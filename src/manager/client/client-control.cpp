/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        client-common.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file is implementation of client-common functions.
 */
#include <dpl/log/log.h>

#include <client-common.h>
#include <message-buffer.h>
#include <protocols.h>

#include <ckm/ckm-control.h>

namespace CKM {

class ControlImpl : public Control {
public:
    ControlImpl() : m_controlConnection(SERVICE_SOCKET_CKM_CONTROL) {}
    ControlImpl(const ControlImpl &) = delete;
    ControlImpl(ControlImpl &&) = delete;
    ControlImpl& operator=(const ControlImpl &) = delete;
    ControlImpl& operator=(ControlImpl &&) = delete;

    virtual int unlockUserKey(uid_t user, const Password &password) {
        return try_catch([&] {
            if((int)user < 0) {
                return CKM_API_ERROR_INPUT_PARAM;
            }

            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::UNLOCK_USER_KEY),
                                                 user,
                                                 password);

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int lockUserKey(uid_t user) {
        return try_catch([&] {
            if((int)user < 0) {
                return CKM_API_ERROR_INPUT_PARAM;
            }

            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::LOCK_USER_KEY), user);

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int removeUserData(uid_t user) {
        return try_catch([&] {
            if((int)user < 0) {
                return CKM_API_ERROR_INPUT_PARAM;
            }

            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::REMOVE_USER_DATA), user);

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int changeUserPassword(uid_t user, const Password &oldPassword, const Password &newPassword) {
        return try_catch([&] {
            if((int)user < 0) {
                return CKM_API_ERROR_INPUT_PARAM;
            }

            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(
                    static_cast<int>(ControlCommand::CHANGE_USER_PASSWORD),
                    user,
                    oldPassword,
                    newPassword);

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int resetUserPassword(uid_t user, const Password &newPassword) {
        return try_catch([&] {
            if((int)user < 0) {
                return CKM_API_ERROR_INPUT_PARAM;
            }

            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(
                    static_cast<int>(ControlCommand::RESET_USER_PASSWORD),
                    user,
                    newPassword);

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int removeApplicationData(const Label &smackLabel) {
        return try_catch([&] {
            if (smackLabel.empty()) {
                return CKM_API_ERROR_INPUT_PARAM;
            }

            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::REMOVE_APP_DATA), smackLabel);

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int updateCCMode() {
        return try_catch([&] {
            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::UPDATE_CC_MODE));

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int setPermission(uid_t user,
                              const Alias &alias,
                              const Label &accessor,
                              PermissionMask permissionMask)
    {
        return try_catch([&] {
            MessageBuffer recv;
            AliasSupport helper(alias);
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::SET_PERMISSION),
                                                 static_cast<int>(user),
                                                 helper.getName(),
                                                 helper.getLabel(),
                                                 accessor,
                                                 permissionMask);

            int retCode = m_controlConnection.processRequest(send.Pop(), recv);
            if (CKM_API_SUCCESS != retCode)
                return retCode;

            int command;
            int counter;
            recv.Deserialize(command, counter, retCode);

            return retCode;
        });
    }

    virtual ~ControlImpl(){}
private:
    CKM::ServiceConnection m_controlConnection;
};

ControlShPtr Control::create() {
    try {
        return std::make_shared<ControlImpl>();
    } catch (const std::bad_alloc &) {
        LogDebug("Bad alloc was caught during ControlImpl creation.");
    } catch (...) {
        LogError("Critical error: Unknown exception was caught druing ControlImpl creation!");
    }
    return ControlShPtr();
}

} // namespace CKM

