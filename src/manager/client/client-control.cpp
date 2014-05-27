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
#include <client-common.h>
#include <message-buffer.h>
#include <protocols.h>

#include <ckm/key-manager.h>

namespace CKM {

class Control::ControlImpl {
public:
    ControlImpl(){}
    ControlImpl(const ControlImpl &) = delete;
    ControlImpl(ControlImpl &&) = delete;
    ControlImpl& operator=(const ControlImpl &) = delete;
    ControlImpl& operator=(ControlImpl &&) = delete;

    static int unlockUserKey(const std::string &user, const RawData &password) {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::UNLOCK_USER_KEY));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, password);

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int lockUserKey(const std::string &user) {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::LOCK_USER_KEY));
            Serialization::Serialize(send, user);

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int removeUserData(const std::string &user) {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::REMOVE_USER_DATA));
            Serialization::Serialize(send, user);

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int changeUserPassword(const std::string &user, const RawData &oldPassword, const RawData &newPassword) {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::CHANGE_USER_PASSWORD));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, oldPassword);
            Serialization::Serialize(send, newPassword);

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    static int resetUserPassword(const std::string &user, const RawData &newPassword) {
        return try_catch([&] {
            if (user.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::RESET_USER_PASSWORD));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, newPassword);

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    virtual ~ControlImpl(){}
};

Control::Control()
  : m_impl(new ControlImpl)
{}

Control::~Control(){}

int Control::unlockUserKey(const std::string &user, const RawData &password) const {
    return m_impl->unlockUserKey(user, password);
}

int Control::lockUserKey(const std::string &user) const {
    return m_impl->lockUserKey(user);
}

int Control::removeUserData(const std::string &user) const {
    return m_impl->removeUserData(user);
}

int Control::changeUserPassword(const std::string &user, const RawData &oldPassword, const RawData &newPassword) const {
    return m_impl->changeUserPassword(user, oldPassword, newPassword);
}

int Control::resetUserPassword(const std::string &user, const RawData &newPassword) const {
    return m_impl->resetUserPassword(user, newPassword);
}

} // namespace CKM

