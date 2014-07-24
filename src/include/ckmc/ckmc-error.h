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

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_KEY_MANAGER_TYPES_MODULE
 * @{
 */


#define KEY_MANAGER_ERROR_CLASS          0x0FFF0000


/**
 * @brief Enumeration for Key Manager Errors.
 * @since_tizen 2.3
 */
typedef enum{
	CKMC_ERROR_NONE                     = TIZEN_ERROR_NONE,               /**< Successful */
	CKMC_ERROR_INVALID_PARAMETER        = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid function parameter */
	CKMC_ERROR_OUT_OF_MEMORY            = TIZEN_ERROR_OUT_OF_MEMORY,      /**< Out of memory */
	CKMC_ERROR_PERMISSION_DENIED        = TIZEN_ERROR_PERMISSION_DENIED,  /**< Permission denied */

	CKMC_ERROR_SOCKET                   = KEY_MANAGER_ERROR_CLASS | 0x01, /**< Socket error between client and Central Key Manager */
	CKMC_ERROR_BAD_REQUEST		        = KEY_MANAGER_ERROR_CLASS | 0x02,  /**< Invalid request from client */
	CKMC_ERROR_BAD_RESPONSE             = KEY_MANAGER_ERROR_CLASS | 0x03, /**< Invalid response from Central Key Manager */
	CKMC_ERROR_SEND_FAILED              = KEY_MANAGER_ERROR_CLASS | 0x04, /**< Transmitting request failed */
	CKMC_ERROR_RECV_FAILED              = KEY_MANAGER_ERROR_CLASS | 0x05, /**< Receiving response failed */
	CKMC_ERROR_AUTHENTICATION_FAILED    = KEY_MANAGER_ERROR_CLASS | 0x06, /**< Authentication between client and manager failed */
	CKMC_ERROR_BUFFER_TOO_SMALL         = KEY_MANAGER_ERROR_CLASS | 0x07, /**< The output buffer size which is passed as parameter is too small */
	CKMC_ERROR_SERVER_ERROR             = KEY_MANAGER_ERROR_CLASS | 0x08, /**< Central Key Manager has been failed for some reason */
	CKMC_ERROR_DB_LOCKED                = KEY_MANAGER_ERROR_CLASS | 0x09, /**< The database was not unlocked - user did not login */
	CKMC_ERROR_DB_ERROR                 = KEY_MANAGER_ERROR_CLASS | 0x0A, /**< An internal error inside the database */
	CKMC_ERROR_DB_ALIAS_EXISTS          = KEY_MANAGER_ERROR_CLASS | 0x0B, /**< Provided alias already exists in the database */
	CKMC_ERROR_DB_ALIAS_UNKNOWN         = KEY_MANAGER_ERROR_CLASS | 0x0C, /**< No data for given alias */
	CKMC_ERROR_VERIFICATION_FAILED      = KEY_MANAGER_ERROR_CLASS | 0x0D, /**< CA certificate(s) were unknown and chain could not be created */
	CKMC_ERROR_INVALID_FORMAT           = KEY_MANAGER_ERROR_CLASS | 0x0E, /**< A provided file or binary has not a valid format */
	CKMC_ERROR_FILE_ACCESS_DENIED       = KEY_MANAGER_ERROR_CLASS | 0x0F, /**< A provided file or binary has not a valid format */
	CKMC_ERROR_UNKNOWN                  = KEY_MANAGER_ERROR_CLASS | 0x10, /**< A provided file or binary has not a valid format */
} key_manager_error_e;


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_CORE_CKMC_ERROR_H_ */
