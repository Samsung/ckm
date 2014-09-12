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
 * @brief       Provides control functions for the key manager.
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
 * @internal
 * @addtogroup CAPI_KEY_MANAGER_CONTROL_MODULE
 * @{
 */

/**
 * @brief Decrypts a user key(DKEK) with password.
 *        A decrypted user key exists only on memory. If this API is called for the first time, a user key will be generated internally.
 *
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/keymanager.admin
 *
 * @remarks The user key is a randomly generated key used in encrypting user data. And the user key is protected by a user's password.
 *
 * @param[in] user      The user ID of a user whose key is decrypted
 * @param[in] password  The password used in decrypting a user key
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                   Successful
 * @retval #CKMC_ERROR_SERVER_ERROR           Failed to unlock user key
 * @retval #CKMC_ERROR_INVALID_PARAMETER      Invalid input parameter
 * @retval #CKMC_ERROR_AUTHENTICATION_FAILED  Not correct password
 * @retval #CKMC_ERROR_PERMISSION_DENIED      Failed to access key manager
 *
 * @see ckmc_lock_user_key()
 * @see ckmc_remove_user_data()
 * @see ckmc_change_user_password()
 * @see ckmc_reset_user_password()
 */
int ckmc_unlock_user_key(uid_t user, const char *password);

/**
 * @brief Removes a decrypted user key(DKEK) from memory
 *
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/keymanager.admin
 *
 * @param[in] user The user ID of a user whose key is removed from memory
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Invalid input parameter
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @see ckmc_unlock_user_key()
 * @see ckmc_remove_user_data()
 * @see ckmc_change_user_password()
 * @see ckmc_reset_user_password()
 */
int ckmc_lock_user_key(uid_t user);

/**
 * @brief Removes user data from Store and erases a user key(DKEK) used for encryption.
 *
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/keymanager.admin
 *
 * @param[in] user The user ID of a user whose data and key are removed
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Invalid input parameter
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @see ckmc_unlock_user_key()
 * @see ckmc_lock_user_key()
 * @see ckmc_change_user_password()
 * @see ckmc_reset_user_password()
 */
int ckmc_remove_user_data(uid_t user);

/**
 * @brief Changes a password for a user.
 *        The key manager decrypts a user key (DKEK) with old password and re-encrypts a user key with new password.
 *
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/keymanager.admin
 *
 * @param[in] user          The user ID of a user whose user key is re-encrypted
 * @param[in] old_password  The password used in decrypting a user key
 * @param[in] new_password  The password used in re-encrypting a user key
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE                   Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER      Invalid input parameter
 * @retval #CKMC_ERROR_AUTHENTICATION_FAILED  Not correct password
 * @retval #CKMC_ERROR_BAD_REQUEST            No information about old password
 * @retval #CKMC_ERROR_PERMISSION_DENIED      Failed to access key manager
 *
 * @see ckmc_unlock_user_key()
 * @see ckmc_lock_user_key()
 * @see ckmc_remove_user_data()
 * @see ckmc_reset_user_password()
 */
int ckmc_change_user_password(uid_t user, const char *old_password, const char *new_password);

/**
 * @brief Changes a password for a user without old password.
 *
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/keymanager.admin
 *
 * @param[in] user          The user ID of a user whose user key is re-encrypted
 * @param[in] new_password  The password used in re-encrypting a user key
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #CKMC_ERROR_NONE               Successful
 * @retval #CKMC_ERROR_INVALID_PARAMETER  Invalid input parameter
 * @retval #CKMC_ERROR_BAD_REQUEST        A user key is not unlocked
 * @retval #CKMC_ERROR_PERMISSION_DENIED  Failed to access key manager
 *
 * @pre User is already logged in and the user key is already loaded into memory in plain text form.
 *
 * @see ckmc_unlock_user_key()
 * @see ckmc_lock_user_key()
 * @see ckmc_remove_user_data()
 * @see ckmc_change_user_password()
 *
 */
int ckmc_reset_user_password(uid_t user, const char *new_password);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif


#endif /* __TIZEN_CORE_CKMC_CONTROL_H */
