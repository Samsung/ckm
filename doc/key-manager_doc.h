/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __TIZEN_CORE_KEY_MANAGER_DOC_H__
#define __TIZEN_CORE_KEY_MANAGER_DOC_H__
/**
 * @ingroup CAPI_SECURITY_FRAMEWORK
 * @defgroup CAPI_KEY_MANAGER_MODULE Key Manager
 * @brief    The key manager provides a secure repository protected by a user’s passwords for keys, certificates, and sensitive data of users and/or their APPs. Additionally, the key manager provides secure cryptographic operations for non-exportable keys without revealing key values to clients.
 *
 * @section CAPI_KEY_MANAGER_MODULE_HEADER Required Header
 * \#include <ckmc/ckmc_control.h>
 * \#include <ckmc/ckmc_manager.h>
 * \#include <ckmc/ckmc_type.h>
 * \#include <ckmc/ckmc_error.h>
 *
 * @section CAPI_KEY_MANAGER_MODULE_OVERVIEW Overview
 * It provides a secure repository for keys, certificates, and sensitive data of users and/or their APPs which are protected by a user’s passwords.
 * Additionally, it provides secure cryptographic operations for non-exportable keys without revealing key values to clients.
 *
 * @image html capi_key_manager_overview_diagram.png
 *
 * The key manager provides three types of API.
 * - secure repository APIs : These APIs provides storing, retrieving, and removing functions for keys, certificates, and data.
 * - secure crypto APIs : These APIs provides additional cryptographic operations(create asymmetric key pair, sign/verify signature, verify certificate)
 * - key manager control APIs : These APIs controls the key manager state(Unlocked/Locked) and reflects the user's password change.
 *
 * Data Store Policy
 *   A client can specify a simple access rules when storing a data in Key Manager.
 *   - Restricted/Non-Restricted:
 *     Data stored in Key Manager can be access on only by its owner if the data is tagged as restricted.
 *     For data tagged as non-restricted, all clients can access on the data.
 *   - Exportable/Non-Exportable:
 *     Only for data tagged as exportable, Key Manager returns the raw value of the data.
 *     If data is tagged as non-exportable, Key Manager doesn’t return its raw value. For that case, Key Manager provides secure cryptographic operations for non-exportable keys without revealing key values to clients.
 *   - Per Key Password:
 *     All data in Key Manager is protected by a user’s password.
 *     Besides, a client can encrypt its data using its own password additionally.
 *     If a client provides a password when storing a data, the data will be encrypted with the password. This password should be provided when get the data from Key Manager.

 * User Login and control API
 *   - When a user logs in, logs out, and changes his/her password, the key manager should be notified.
 *   - Only privileged APPs such as LockScreen APP or Setting APP can notify to key manager using the control APIs.
 *   - When a user logs in, the key manager decrypts the user's DKEK with a user password.
 *     So during the loggin period, any client can access its data which is protected by a user's password(technically encrypted with the client's ADEK).
 *   - When a user logs out, the key manager removes the user's DKEK from memory.
 *     Therefore, any clients cannot access to any data.
 *   - When a user change his/her password, the key manager re-encrypted the user's DKEK with a new password.
 */

#endif /* __TIZEN_CORE_KEY_MANAGER_DOC_H__ */
