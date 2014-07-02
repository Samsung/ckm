/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckm-manager.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Main header file for client library.
 */
#pragma once

#include <string>
#include <vector>
#include <memory>

#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>

// Central Key Manager namespace
namespace CKM {

// used by login manager to unlock user data with global password
class Control
{
public:
    Control();
    // decrypt user key with password
    int unlockUserKey(uid_t user, const std::string &password) const;

    // remove user key from memory
    int lockUserKey(uid_t user) const;

    // remove user data from Store and erase key used for encryption
    int removeUserData(uid_t user) const;

    // change password for user
    int changeUserPassword(uid_t user, const std::string &oldPassword, const std::string &newPassword) const;

    // This is work around for security-server api - resetPassword that may be called without passing oldPassword.
    // This api should not be supported on tizen 3.0
    // User must be already logged in and his DKEK is already loaded into memory in plain text form.
    // The service will use DKEK in plain text and encrypt it in encrypted form (using new password).
    int resetUserPassword(uid_t user, const std::string &newPassword) const;

    virtual ~Control();
private:
    class ControlImpl;
    std::shared_ptr<ControlImpl> m_impl;
};

} // namespace CKM

