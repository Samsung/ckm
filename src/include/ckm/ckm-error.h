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
 * @file    ckm-manager.h
 * @version 1.0
 * @brief   This file contains APIs of the Central Key Manager
*/
#ifndef _CKM_ERROR_H_
#define _CKM_ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name Return Codes
 * exported by the foundation API.
 * result codes begin with the start error code and extend into negative direction.
 * @{
*/
#define CKM_API_SUCCESS 0
/*! \brief   indicating the result of the one specific API is successful */
#define CKM_API_ERROR_SOCKET -1

/*! \brief   indicating the socket between client and Central Key Manager failed  */
#define CKM_API_ERROR_BAD_REQUEST -2

/*! \brief   indicating the response from Central Key Manager is malformed */
#define CKM_API_ERROR_BAD_RESPONSE -3

/*! \brief   indicating the transmitting request failed */
/* deprecated unused */
#define CKM_API_ERROR_SEND_FAILED -4

/*! \brief   indicating the receiving response failed */
/* deprecated unused */
#define CKM_API_ERROR_RECV_FAILED -5

/*! \brief   indicating the authentication between client and manager failed */
#define CKM_API_ERROR_AUTHENTICATION_FAILED -6

/*! \brief   indicating the API's input parameter is malformed */
#define CKM_API_ERROR_INPUT_PARAM -7

/*! \brief   indicating the output buffer size which is passed as parameter is too small */
#define CKM_API_ERROR_BUFFER_TOO_SMALL -8

/*! \brief   indicating system  is running out of memory state */
#define CKM_API_ERROR_OUT_OF_MEMORY -9

/*! \brief   indicating the access has been denied by Central Key Manager */
#define CKM_API_ERROR_ACCESS_DENIED -10

/*! \brief   indicating Central Key Manager has been failed for some reason */
#define CKM_API_ERROR_SERVER_ERROR -11

/*! \brief   indicating the database was not unlocked - user did not login */
#define CKM_API_ERROR_DB_LOCKED -12

/*! \brief   indicating an internal error inside the database */
#define CKM_API_ERROR_DB_ERROR -13

/*! \brief   indicating that provided alias already exists in the database */
#define CKM_API_ERROR_DB_ALIAS_EXISTS -14

/*! \brief   indicating that request give to database returned no result */
#define CKM_API_ERROR_DB_ALIAS_UNKNOWN -15

/*! \brief   indicating that CA certificate(s) were unknown and chain could not be created */
#define CKM_API_ERROR_VERIFICATION_FAILED -16

/*! \brief   indicating that a provided file or binary has not a valid format */
#define CKM_API_ERROR_INVALID_FORMAT -17

/*! \brief   indicating that provided file doesn't exists or cannot be accessed in the file system */
#define CKM_API_ERROR_FILE_ACCESS_DENIED -18

#define CKM_API_OCSP_STATUS_GOOD                (1<<0)
#define CKM_API_OCSP_STATUS_UNSUPPORTED         (1<<1)
#define CKM_API_OCSP_STATUS_UNKNOWN             (1<<2)
#define CKM_API_OCSP_STATUS_REVOKED             (1<<3)
#define CKM_API_OCSP_STATUS_NET_ERROR           (1<<4)
#define CKM_API_OCSP_STATUS_INVALID_URL         (1<<5)
#define CKM_API_OCSP_STATUS_INVALID_RESPONSE    (1<<6)
#define CKM_API_OCSP_STATUS_REMOTE_ERROR        (1<<7)
#define CKM_API_OCSP_STATUS_INTERNAL_ERROR      (1<<8)

/*! \brief   indicating the error with unknown reason */
#define CKM_API_ERROR_UNKNOWN -255
/** @}*/

#ifdef __cplusplus
}
#endif

#endif
