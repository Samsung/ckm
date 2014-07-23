/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file    ckmc-error.h
 * @version 1.0
 * @brief   This file contains error codes of the Key Manager
*/
#ifndef __TIZEN_CORE_CKMC_ERROR_H_
#define __TIZEN_CORE_CKMC_ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_KEY_MANAGER_TYPES_MODULE
 * @{
 */

/**
 * @brief Indicates the result of the one specific API is successful
 * @since_tizen 2.3
 */
#define CKMC_SUCCESS 0

/**
 * @brief Indicates the socket between client and Central Key Manager failed
 * @since_tizen 2.3
 */
#define CKMC_ERROR_SOCKET -1

/**
 * @brief Indicates the request from client is malformed
 * @since_tizen 2.3
 */
#define CKMC_ERROR_BAD_REQUEST -2

/**
 * @brief Indicates the response from Central Key Manager is malformed
 * @since_tizen 2.3
 */
#define CKMC_ERROR_BAD_RESPONSE -3

/**
 * @brief Indicates the transmitting request failed.
 * @since_tizen 2.3
 */
#define CKMC_ERROR_SEND_FAILED -4

/**
 * @brief Indicates the receiving response failed.
 * @since_tizen 2.3
 */
#define CKMC_ERROR_RECV_FAILED -5

/**
 * @brief Indicates the authentication between client and manager failed.
 * @since_tizen 2.3
 */
#define CKMC_ERROR_AUTHENTICATION_FAILED -6

/**
 * @brief Indicates the API's input parameter is malformed
 * @since_tizen 2.3
 */
#define CKMC_ERROR_INPUT_PARAM -7

/**
 * @brief Indicates the output buffer size which is passed as parameter is too small
 * @since_tizen 2.3
 */
#define CKMC_ERROR_BUFFER_TOO_SMALL -8

/**
 * @brief Indicates system is running out of memory state
 * @since_tizen 2.3
 */
#define CKMC_ERROR_OUT_OF_MEMORY -9

/**
 * @brief Indicates the access has been denied by Central Key Manager
 * @since_tizen 2.3
 */
#define CKMC_ERROR_ACCESS_DENIED -10

/**
 * @brief Indicates Central Key Manager has been failed for some reason
 * @since_tizen 2.3
 */
#define CKMC_ERROR_SERVER_ERROR -11

/**
 * @brief Indicates the database was not unlocked - user did not login
 * @since_tizen 2.3
 */
#define CKMC_ERROR_DB_LOCKED -12

/**
 * @brief Indicates an internal error inside the database
 * @since_tizen 2.3
 */
#define CKMC_ERROR_DB_ERROR -13

/**
 * @brief Indicates that provided alias already exists in the database
 * @since_tizen 2.3
 */
#define CKMC_ERROR_DB_ALIAS_EXISTS -14

/**
 * @brief Indicates that request given to database returned no result
 * @since_tizen 2.3
 */
#define CKMC_ERROR_DB_ALIAS_UNKNOWN -15

/**
 * @brief Indicates that CA certificate(s) were unknown and chain could not be created
 * @since_tizen 2.3
 */
#define CKMC_ERROR_VERIFICATION_FAILED -16

/**
 * @brief Indicates that a provided file or binary has not a valid format
 * @since_tizen 2.3
 */
#define CKMC_ERROR_INVALID_FORMAT -17

/**
 * @brief Indicates that provided file doesn't exists or cannot be accessed in the file system
 * @since_tizen 2.3
 */
#define CKMC_ERROR_FILE_ACCESS_DENIED -18

/**
 * @brief Indicates the error with unknown reason
 * @since_tizen 2.3
 */
#define CKMC_ERROR_UNKNOWN -255


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_CORE_CKMC_ERROR_H_ */
