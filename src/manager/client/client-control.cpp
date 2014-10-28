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
    ControlImpl(){}
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
            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

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
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::LOCK_USER_KEY),
                                                 user);
            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

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
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::REMOVE_USER_DATA),
                                                 user);
            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

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

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

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

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

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
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::REMOVE_APP_DATA),
                                                 smackLabel);
            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int updateCCMode() {
        return try_catch([&] {
            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::UPDATE_CC_MODE));
            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            recv.Deserialize(retCode);

            return retCode;
        });
    }

    virtual int allowAccess(uid_t user,
                            const Label &owner,
                            const Alias &alias,
                            const Label &accessor,
                            AccessRight granted)
    {
        return try_catch([&] {
            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::ALLOW_ACCESS),
                                                 static_cast<int>(user),
                                                 owner,
                                                 alias,
                                                 accessor,
                                                 static_cast<int>(granted));
            int retCode = sendToServer(
                    SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            int command;
            int counter;
            recv.Deserialize(command, counter, retCode);
            return retCode;
        });
    }

    virtual int denyAccess(uid_t user,
                           const Label &owner,
                           const Alias &alias,
                           const Label &accessor)
    {
        return try_catch([&] {
            MessageBuffer recv;
            auto send = MessageBuffer::Serialize(static_cast<int>(ControlCommand::DENY_ACCESS),
                                                 static_cast<int>(user),
                                                 owner,
                                                 alias,
                                                 accessor);
            int retCode = sendToServer(
                    SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            int command;
            int counter;
            recv.Deserialize(command, counter, retCode);
            return retCode;
        });
    }

    virtual ~ControlImpl(){}
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

