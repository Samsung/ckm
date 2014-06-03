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
 * @file        ckm-logic.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#pragma once

#include <string>
#include <vector>
#include <message-buffer.h>
#include <protocols.h>
#include <ckm/ckm-type.h>
#include <connection-info.h>

namespace CKM {

class CKMLogic {
public:
    CKMLogic();
    CKMLogic(const CKMLogic &) = delete;
    CKMLogic(CKMLogic &&) = delete;
    CKMLogic& operator=(const CKMLogic &) = delete;
    CKMLogic& operator=(CKMLogic &&) = delete;
    virtual ~CKMLogic();

    RawBuffer unlockUserKey(const std::string &user, const std::string &password);

    RawBuffer lockUserKey(const std::string &user);

    RawBuffer removeUserData(const std::string &user);

    RawBuffer changeUserPassword(
        const std::string &user,
        const std::string &oldPassword,
        const std::string &newPassword);

    RawBuffer resetUserPassword(
        const std::string &user,
        const std::string &newPassword);

    RawBuffer saveData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias,
        const RawBuffer &key,
        const PolicySerializable &policy);

    RawBuffer removeData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias);

    RawBuffer getData(
        Credentials &cred,
        int commandId,
        DBDataType dataType,
        const Alias &alias,
        const std::string &password);

private:

};

} // namespace CKM

