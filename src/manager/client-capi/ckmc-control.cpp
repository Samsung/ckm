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

KEY_MANAGER_CAPI
int ckmc_unlock_user_key(uid_t user, const char *password)
{
	auto control = CKM::Control::create();
	return control->unlockUserKey(user, std::string(password));
}

KEY_MANAGER_CAPI
int ckmc_lock_user_key(uid_t user)
{
	auto control = CKM::Control::create();
	return control->lockUserKey(user);
}

KEY_MANAGER_CAPI
int ckmc_remove_user_data(uid_t user)
{
	auto control = CKM::Control::create();
	return control->removeUserData(user);
}

KEY_MANAGER_CAPI
int ckmc_change_user_password(uid_t user, const char *oldPassword, const char *newPassword)
{
	auto control = CKM::Control::create();
	return control->changeUserPassword(user, std::string(oldPassword), std::string(newPassword));
}

KEY_MANAGER_CAPI
int ckmc_reset_user_password(uid_t user, const char *newPassword)
{
	auto control = CKM::Control::create();
	return control->resetUserPassword(user, std::string(newPassword));
}



