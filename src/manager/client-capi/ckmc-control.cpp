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
 * @file        ckmc-control.h
 * @author      Yuseok Jeon(yuseok.jeon@samsung.com)
 * @version     1.0
 * @brief       provides conversion methods to C from C++ for key-manager control functions.
 */

#include <ckm/ckm-control.h>
#include <ckmc/ckmc-control.h>
#include <ckmc/ckmc-error.h>
#include <ckmc-type-converter.h>
#include <ckm/ckm-type.h>
#include <client-common.h>

CKM::Password _toPasswordStr(const char *str)
{
    if (str == NULL)
        return CKM::Password();
    return CKM::Password(str);
}

KEY_MANAGER_CAPI
int ckmc_unlock_user_key(uid_t user, const char *password)
{
    auto control = CKM::Control::create();
    int ret = control->unlockUserKey(user, _toPasswordStr(password));
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_lock_user_key(uid_t user)
{
    auto control = CKM::Control::create();
    int ret = control->lockUserKey(user);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_remove_user_data(uid_t user)
{
    auto control = CKM::Control::create();
    int ret = control->removeUserData(user);
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_change_user_password(uid_t user, const char *oldPassword, const char *newPassword)
{
    auto control = CKM::Control::create();
    int ret = control->changeUserPassword(user,
                                          _toPasswordStr(oldPassword),
                                          _toPasswordStr(newPassword));
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_reset_user_password(uid_t user, const char *newPassword)
{
    auto control = CKM::Control::create();
    int ret = control->resetUserPassword(user, _toPasswordStr(newPassword));
    return to_ckmc_error(ret);
}

KEY_MANAGER_CAPI
int ckmc_allow_access_by_adm(uid_t user, const char* owner, const char *alias, const char *accessor, ckmc_access_right_e granted)
{
    if(!owner || !alias)
        return CKMC_ERROR_INVALID_PARAMETER;

    // if label given twice, service will return an error
    return ckmc_set_permission_by_adm(user, CKM::AliasSupport::merge(CKM::Label(owner), CKM::Name(alias)).c_str(), accessor, granted);
}

KEY_MANAGER_CAPI
int ckmc_set_permission_by_adm(uid_t user, const char *alias, const char *accessor, int permissions)
{
    if (!alias || !accessor)
        return CKMC_ERROR_INVALID_PARAMETER;

    auto control = CKM::Control::create();
    return to_ckmc_error(control->setPermission(user, alias, accessor, permissions));
}

KEY_MANAGER_CAPI
int ckmc_deny_access_by_adm(uid_t user, const char* owner, const char *alias, const char *accessor)
{
    if(!owner || !alias)
        return CKMC_ERROR_INVALID_PARAMETER;

    // if label given twice, service will return an error
    auto control = CKM::Control::create();
    return to_ckmc_error(control->setPermission(
                                user,
                                CKM::AliasSupport::merge(CKM::Label(owner), CKM::Name(alias)).c_str(),
                                accessor,
                                CKM::Permission::NONE));
}
