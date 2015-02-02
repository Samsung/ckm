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
 * @brief   This file contains error codes of the Key Manager.
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

/**
 * @brief Enumeration for Key Manager Errors.
 * @since_tizen 2.3
 */


// MJK TODO: this should be moved into /usr/include/tizen_error.h
#ifndef TIZEN_ERROR_KEY_MANAGER
/** Tizen Key Manager Error */
#define TIZEN_ERROR_KEY_MANAGER     -0x01E10000
#endif


typedef enum{
	CKMC_ERROR_NONE                     = TIZEN_ERROR_NONE,               /**< Successful */
	CKMC_ERROR_INVALID_PARAMETER        = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid function parameter */
	CKMC_ERROR_OUT_OF_MEMORY            = TIZEN_ERROR_OUT_OF_MEMORY,      /**< Out of memory */
	CKMC_ERROR_PERMISSION_DENIED        = TIZEN_ERROR_PERMISSION_DENIED,  /**< Permission denied */

	CKMC_ERROR_SOCKET                   = TIZEN_ERROR_KEY_MANAGER | 0x01, /**< Socket error between client and Central Key Manager */
	CKMC_ERROR_BAD_REQUEST              = TIZEN_ERROR_KEY_MANAGER | 0x02,  /**< Invalid request from client */
	CKMC_ERROR_BAD_RESPONSE             = TIZEN_ERROR_KEY_MANAGER | 0x03, /**< Invalid response from Central Key Manager */
	CKMC_ERROR_SEND_FAILED              = TIZEN_ERROR_KEY_MANAGER | 0x04, /**< Transmitting request failed */
	CKMC_ERROR_RECV_FAILED              = TIZEN_ERROR_KEY_MANAGER | 0x05, /**< Receiving response failed */
	CKMC_ERROR_AUTHENTICATION_FAILED    = TIZEN_ERROR_KEY_MANAGER | 0x06, /**< Authentication between client and manager failed */
	CKMC_ERROR_BUFFER_TOO_SMALL         = TIZEN_ERROR_KEY_MANAGER | 0x07, /**< The output buffer size which is passed as parameter is too small */
	CKMC_ERROR_SERVER_ERROR             = TIZEN_ERROR_KEY_MANAGER | 0x08, /**< Central Key Manager has been failed for some reason */
	CKMC_ERROR_DB_LOCKED                = TIZEN_ERROR_KEY_MANAGER | 0x09, /**< The database was not unlocked - user did not login */
	CKMC_ERROR_DB_ERROR                 = TIZEN_ERROR_KEY_MANAGER | 0x0A, /**< An internal error inside the database */
	CKMC_ERROR_DB_ALIAS_EXISTS          = TIZEN_ERROR_KEY_MANAGER | 0x0B, /**< Provided alias already exists in the database */
	CKMC_ERROR_DB_ALIAS_UNKNOWN         = TIZEN_ERROR_KEY_MANAGER | 0x0C, /**< No data for given alias */
	CKMC_ERROR_VERIFICATION_FAILED      = TIZEN_ERROR_KEY_MANAGER | 0x0D, /**< CA certificate(s) were unknown and chain could not be created */
	CKMC_ERROR_INVALID_FORMAT           = TIZEN_ERROR_KEY_MANAGER | 0x0E, /**< A provided file or binary has not a valid format */
	CKMC_ERROR_FILE_ACCESS_DENIED       = TIZEN_ERROR_KEY_MANAGER | 0x0F, /**< A provided file doesn't exist or cannot be accessed in the file system */
	CKMC_ERROR_NOT_EXPORTABLE           = TIZEN_ERROR_KEY_MANAGER | 0x10, /**< Key is not exportable. It could not be returned to client */
	CKMC_ERROR_FILE_SYSTEM              = TIZEN_ERROR_KEY_MANAGER | 0x11, /**< Save key/certificate/pkcs12 failed because of file system error */
	CKMC_ERROR_UNKNOWN                  = TIZEN_ERROR_KEY_MANAGER | 0xFF, /**< The error with unknown reason */
} key_manager_error_e;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_CORE_CKMC_ERROR_H_ */
