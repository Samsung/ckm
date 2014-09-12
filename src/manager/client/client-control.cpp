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

#include <ckm/ckm-control.h>

namespace CKM {

class ControlImpl : public Control {
public:
    ControlImpl(){}
    ControlImpl(const ControlImpl &) = delete;
    ControlImpl(ControlImpl &&) = delete;
    ControlImpl& operator=(const ControlImpl &) = delete;
    ControlImpl& operator=(ControlImpl &&) = delete;

    virtual int unlockUserKey(uid_t user, const std::string &password) const {
        return try_catch([&] {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::UNLOCK_USER_KEY));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, password);
            int retCode;

            if((int)user < 0) {
                retCode = CKM_API_ERROR_INPUT_PARAM;
                return retCode;
            }

            retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    virtual int lockUserKey(uid_t user) const {
        return try_catch([&] {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::LOCK_USER_KEY));
            Serialization::Serialize(send, user);
            int retCode;

            if((int)user < 0) {
                retCode = CKM_API_ERROR_INPUT_PARAM;
                return retCode;
            }

            retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    virtual int removeUserData(uid_t user) const {
        return try_catch([&] {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::REMOVE_USER_DATA));
            Serialization::Serialize(send, user);
            int retCode;

            if((int)user < 0) {
                retCode = CKM_API_ERROR_INPUT_PARAM;
                return retCode;
            }

            retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    virtual int changeUserPassword(uid_t user, const std::string &oldPassword, const std::string &newPassword) const {
        return try_catch([&] {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::CHANGE_USER_PASSWORD));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, oldPassword);
            Serialization::Serialize(send, newPassword);
            int retCode;

            if((int)user < 0) {
                retCode = CKM_API_ERROR_INPUT_PARAM;
                return retCode;
            }

            retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    virtual int resetUserPassword(uid_t user, const std::string &newPassword) const {
        return try_catch([&] {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(ControlCommand::RESET_USER_PASSWORD));
            Serialization::Serialize(send, user);
            Serialization::Serialize(send, newPassword);
            int retCode;

            if((int)user < 0) {
                retCode = CKM_API_ERROR_INPUT_PARAM;
                return retCode;
            }

            retCode = sendToServer(
                SERVICE_SOCKET_CKM_CONTROL,
                send.Pop(),
                recv);

            if (CKM_API_SUCCESS != retCode) {
                return retCode;
            }

            Deserialization::Deserialize(recv, retCode);

            return retCode;
        });
    }

    virtual ~ControlImpl(){}

};

ControlShPtr Control::create() {
    return ControlShPtr(new ControlImpl());
}

} // namespace CKM

