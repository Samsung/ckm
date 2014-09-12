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
#include <dpl/serialization.h>

#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>

#include <ckm-logic.h>
namespace CKM {

CKMLogic::CKMLogic(){}
CKMLogic::~CKMLogic(){}

RawBuffer CKMLogic::unlockUserKey(const std::string &user, const std::string &password) {
    (void)user;
    (void)password;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    return response.Pop();
}

RawBuffer CKMLogic::lockUserKey(const std::string &user) {
    (void)user;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    return response.Pop();
}

RawBuffer CKMLogic::removeUserData(const std::string &user) {
    (void)user;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    return response.Pop();
}

RawBuffer CKMLogic::changeUserPassword(
    const std::string &user,
    const std::string &oldPassword,
    const std::string &newPassword)
{
    (void)user;
    (void)oldPassword;
    (void)newPassword;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    return response.Pop();
}

RawBuffer CKMLogic::resetUserPassword(
    const std::string &user,
    const std::string &newPassword)
{
    (void)user;
    (void)newPassword;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    return response.Pop();
}

RawBuffer CKMLogic::saveData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias,
    const RawBuffer &key,
    const PolicySerializable &policy)
{
    (void)cred;
    (void)alias;
    (void)key;
    (void)policy;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::SAVE));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    Serialization::Serialize(response, static_cast<int>(dataType));

    return response.Pop();
}

RawBuffer CKMLogic::removeData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias)
{
    (void)cred;
    (void)alias;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::REMOVE));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    Serialization::Serialize(response, static_cast<int>(dataType));

    return response.Pop();
}

RawBuffer CKMLogic::getData(
    Credentials &cred,
    int commandId,
    DBDataType dataType,
    const Alias &alias,
    const std::string &password)
{
    (void)cred;
    (void)alias;
    (void)password;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    Serialization::Serialize(response, static_cast<int>(dataType));
    Serialization::Serialize(response, RawBuffer());
    return response.Pop();
}

RawBuffer CKMLogic::getDataList(
    Credentials &cred,
    int commandId,
    DBDataType dataType)
{
    (void)cred;

    MessageBuffer response;
    Serialization::Serialize(response, static_cast<int>(LogicCommand::GET_LIST));
    Serialization::Serialize(response, commandId);
    Serialization::Serialize(response, static_cast<int>(KEY_MANAGER_API_SUCCESS));
    Serialization::Serialize(response, static_cast<int>(dataType));
    Serialization::Serialize(response, AliasVector());
    return response.Pop();
}

} // namespace CKM

