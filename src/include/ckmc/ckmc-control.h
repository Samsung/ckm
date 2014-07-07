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
 * @brief       provides functions which are able to control key-manager daemon.
 */

#ifndef CKMC_CONTROL_H
#define CKMC_CONTROL_H


#include <sys/types.h>
#include <ckmc/ckmc-error.h>
#include <ckmc/ckmc-type.h>


#ifdef __cplusplus
extern "C" {
#endif


// decrypt user key with password
int ckm_unlock_user_key(uid_t user, const char *password);

// remove user key from memory
int ckm_lock_user_key(uid_t user);

// remove user data from Store and erase key used for encryption
int ckm_remove_user_data(uid_t user);

// change password for user
int ckm_change_user_password(uid_t user, const char *old_password, const char *new_password);

// This is work around for security-server api - resetPassword that may be called without passing oldPassword.
// This api should not be supported on tizen 3.0
// User must be already logged in and his DKEK is already loaded into memory in plain text form.
// The service will use DKEK in plain text and encrypt it in encrypted form (using new password).
int ckm_reset_user_password(uid_t user, const char *new_password);



#ifdef __cplusplus
}
#endif


#endif /* CKMC_CONTROL_H */
