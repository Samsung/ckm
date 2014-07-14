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
 * @version     1.0
 * @brief       provides control functions for the key manager.
 */

#ifndef __TIZEN_CORE_CKMC_CONTROL_H
#define __TIZEN_CORE_CKMC_CONTROL_H


#include <sys/types.h>
#include <ckmc/ckmc-error.h>
#include <ckmc/ckmc-type.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_KEY_MANAGER_MODULE
 * @{
 */

/**
 * @brief Decrypts a user key with password. A decrypted user key exists only on memory. If this API is called for the first time, a user key will be generated internally.
 *
 * @remarks The user key is a randomly generated key used in encrypting user data. And the user key is protected by a user's password.
 *
 * @param[in] user is a uid of a user whose key is decrypted.
 * @param[in] password is used in decrypting a user key.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_SERVER_ERROR failed to unlock user key
 * @retval #CKM_API_ERROR_INPUT_PARAM invalid input parameter
 * @retval #CKM_API_ERROR_AUTHENTICATION_FAILED not correct password
 *
 * @see ckm_lock_user_key()
 * @see ckm_remove_user_data()
 * @see ckm_change_user_password()
 * @see ckm_reset_user_password()
 */
int ckm_unlock_user_key(uid_t user, const char *password);

/**
 * @brief remove a decrypted user key from memory
 *
 * @param[in] user is a uid of a user whose key is removed from memory.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM invalid input parameter
 *
 * @see ckm_unlock_user_key()
 * @see ckm_remove_user_data()
 * @see ckm_change_user_password()
 * @see ckm_reset_user_password()
 */
int ckm_lock_user_key(uid_t user);

/**
 * @brief remove user data from Store and erase a user key used for encryption
 *
 * @param[in] user is a uid of a user whose data and key are removed
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM invalid input parameter
 *
 * @see ckm_unlock_user_key()
 * @see ckm_lock_user_key()
 * @see ckm_change_user_password()
 * @see ckm_reset_user_password()
 */
int ckm_remove_user_data(uid_t user);

/**
 * @brief change a password for a user. key manager decrypts a user key with old password and re-encrypts a user key with new password.
 *
 * @param[in] user is a uid of a user whose user key is re-encrypted
 * @param[in] old_password is used in decrypting a user key.
 * @param[in] new_password is used in re-encrypting a user key.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM invalid input parameter
 * @retval #CKM_API_ERROR_AUTHENTICATION_FAILED not correct password
 * @retval #CKM_API_ERROR_BAD_REQUEST no information about old password
 *
 * @see ckm_unlock_user_key()
 * @see ckm_lock_user_key()
 * @see ckm_remove_user_data()
 * @see ckm_reset_user_password()
 */
int ckm_change_user_password(uid_t user, const char *old_password, const char *new_password);

/**
 * @brief change a password for a user without old password.
 *
 * @param[in] user is a uid of a user whose user key is re-encrypted
 * @param[in] new_password is used in re-encrypting a user key.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #CKM_API_SUCCESS Successful
 * @retval #CKM_API_ERROR_INPUT_PARAM invalid input parameter
 * @retval #CKM_API_ERROR_BAD_REQUEST a user key is not unlocked.
 *
 * @pre User must be already logged in and his user key is already loaded into memory in plain text form.
 *
 * @see ckm_unlock_user_key()
 * @see ckm_lock_user_key()
 * @see ckm_remove_user_data()
 * @see ckm_change_user_password()
 */
int ckm_reset_user_password(uid_t user, const char *newPassword);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif


#endif /* __TIZEN_CORE_CKMC_CONTROL_H */
