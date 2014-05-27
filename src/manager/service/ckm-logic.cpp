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
 * @file        ckm-logic.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#include <ckm-logic.h>

namespace CKM {

CKMLogic::CKMLogic(){}
CKMLogic::~CKMLogic(){}

RawBuffer CKMLogic::unlockUserKey(const std::string &user, const RawBuffer &password) {
    (void)user;
    (void)password;
    return RawBuffer();
}

RawBuffer CKMLogic::lockUserKey(const std::string &user) {
    (void)user;
    return RawBuffer();
}

RawBuffer CKMLogic::removeUserData(const std::string &user) {
    (void)user;
    return RawBuffer();
}

RawBuffer CKMLogic::changeUserPassword(
    const std::string &user,
    const RawBuffer &oldPassword,
    const RawBuffer &newPassword)
{
    (void)user;
    (void)oldPassword;
    (void)newPassword;
    return RawBuffer();
}

RawBuffer CKMLogic::resetUserPassword(
    const std::string &user,
    const RawBuffer &newPassword)
{
    (void)user;
    (void)newPassword;
    return RawBuffer();
}

} // namespace CKM

