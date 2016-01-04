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
 * @file        ckmc-type-converter.cpp
 * @author      Dongsun Lee(ds73.lee@samsung.com)
 * @version     1.0
 * @brief       new and free methods for the struct of CAPI
 */

#include <ckmc/ckmc-type.h>
#include <ckmc-type-converter.h>

int to_ckm_error(int ckmc_error)
{
    switch (ckmc_error) {
    case CKMC_ERROR_NONE:                  return CKM_API_SUCCESS;
    case CKMC_ERROR_SOCKET:                return CKM_API_ERROR_SOCKET;
    case CKMC_ERROR_BAD_REQUEST:           return CKM_API_ERROR_BAD_REQUEST;
    case CKMC_ERROR_BAD_RESPONSE:          return CKM_API_ERROR_BAD_RESPONSE;
    case CKMC_ERROR_SEND_FAILED:           return CKM_API_ERROR_SEND_FAILED;
    case CKMC_ERROR_RECV_FAILED:           return CKM_API_ERROR_RECV_FAILED;
    case CKMC_ERROR_AUTHENTICATION_FAILED: return CKM_API_ERROR_AUTHENTICATION_FAILED;
    case CKMC_ERROR_INVALID_PARAMETER:     return CKM_API_ERROR_INPUT_PARAM;
    case CKMC_ERROR_BUFFER_TOO_SMALL:      return CKM_API_ERROR_BUFFER_TOO_SMALL;
    case CKMC_ERROR_OUT_OF_MEMORY:         return CKM_API_ERROR_OUT_OF_MEMORY;
    case CKMC_ERROR_PERMISSION_DENIED:     return CKM_API_ERROR_ACCESS_DENIED;
    case CKMC_ERROR_SERVER_ERROR:          return CKM_API_ERROR_SERVER_ERROR;
    case CKMC_ERROR_DB_LOCKED:             return CKM_API_ERROR_DB_LOCKED;
    case CKMC_ERROR_DB_ERROR:              return CKM_API_ERROR_DB_ERROR;
    case CKMC_ERROR_DB_ALIAS_EXISTS:       return CKM_API_ERROR_DB_ALIAS_EXISTS;
    case CKMC_ERROR_DB_ALIAS_UNKNOWN:      return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
    case CKMC_ERROR_VERIFICATION_FAILED:   return CKM_API_ERROR_VERIFICATION_FAILED;
    case CKMC_ERROR_INVALID_FORMAT:        return CKM_API_ERROR_INVALID_FORMAT;
    case CKMC_ERROR_FILE_ACCESS_DENIED:    return CKM_API_ERROR_FILE_ACCESS_DENIED;
    case CKMC_ERROR_NOT_EXPORTABLE:        return CKM_API_ERROR_NOT_EXPORTABLE;
    case CKMC_ERROR_FILE_SYSTEM:           return CKM_API_ERROR_FILE_SYSTEM;
    case CKMC_ERROR_NOT_SUPPORTED:         return CKM_API_ERROR_NOT_SUPPORTED;
    case CKMC_ERROR_UNKNOWN:               return CKM_API_ERROR_UNKNOWN;
    }
    return CKMC_ERROR_UNKNOWN;
}

int to_ckmc_error(int ckm_error)
{
    switch (ckm_error) {
    case CKM_API_SUCCESS:                     return CKMC_ERROR_NONE;
    case CKM_API_ERROR_SOCKET:                return CKMC_ERROR_SOCKET;
    case CKM_API_ERROR_BAD_REQUEST:           return CKMC_ERROR_BAD_REQUEST;
    case CKM_API_ERROR_BAD_RESPONSE:          return CKMC_ERROR_BAD_RESPONSE;
    case CKM_API_ERROR_SEND_FAILED:           return CKMC_ERROR_SEND_FAILED;
    case CKM_API_ERROR_RECV_FAILED:           return CKMC_ERROR_RECV_FAILED;
    case CKM_API_ERROR_AUTHENTICATION_FAILED: return CKMC_ERROR_AUTHENTICATION_FAILED;
    case CKM_API_ERROR_INPUT_PARAM:           return CKMC_ERROR_INVALID_PARAMETER;
    case CKM_API_ERROR_BUFFER_TOO_SMALL:      return CKMC_ERROR_BUFFER_TOO_SMALL;
    case CKM_API_ERROR_OUT_OF_MEMORY:         return CKMC_ERROR_OUT_OF_MEMORY;
    case CKM_API_ERROR_ACCESS_DENIED:         return CKMC_ERROR_PERMISSION_DENIED;
    case CKM_API_ERROR_SERVER_ERROR:          return CKMC_ERROR_SERVER_ERROR;
    case CKM_API_ERROR_DB_LOCKED:             return CKMC_ERROR_DB_LOCKED;
    case CKM_API_ERROR_DB_ERROR:              return CKMC_ERROR_DB_ERROR;
    case CKM_API_ERROR_DB_ALIAS_EXISTS:       return CKMC_ERROR_DB_ALIAS_EXISTS;
    case CKM_API_ERROR_DB_ALIAS_UNKNOWN:      return CKMC_ERROR_DB_ALIAS_UNKNOWN;
    case CKM_API_ERROR_VERIFICATION_FAILED:   return CKMC_ERROR_VERIFICATION_FAILED;
    case CKM_API_ERROR_INVALID_FORMAT:        return CKMC_ERROR_INVALID_FORMAT;
    case CKM_API_ERROR_FILE_ACCESS_DENIED:    return CKMC_ERROR_FILE_ACCESS_DENIED;
    case CKM_API_ERROR_NOT_EXPORTABLE:        return CKMC_ERROR_NOT_EXPORTABLE;
    case CKM_API_ERROR_FILE_SYSTEM:           return CKMC_ERROR_FILE_SYSTEM;
    case CKM_API_ERROR_NOT_SUPPORTED:         return CKMC_ERROR_NOT_SUPPORTED;
    case CKM_API_ERROR_UNKNOWN:               return CKMC_ERROR_UNKNOWN;
    }
    return CKMC_ERROR_UNKNOWN;
}

ckmc_ocsp_status_e to_ckmc_ocsp_status(int ckm_ocsp_status)
{
    switch (ckm_ocsp_status) {
    case CKM_API_OCSP_STATUS_GOOD:             return CKMC_OCSP_STATUS_GOOD;
    case CKM_API_OCSP_STATUS_UNSUPPORTED:      return CKMC_OCSP_ERROR_UNSUPPORTED;
    case CKM_API_OCSP_STATUS_REVOKED:          return CKMC_OCSP_STATUS_REVOKED;
    case CKM_API_OCSP_STATUS_NET_ERROR:        return CKMC_OCSP_ERROR_NET;
    case CKM_API_OCSP_STATUS_INVALID_URL:      return CKMC_OCSP_ERROR_INVALID_URL;
    case CKM_API_OCSP_STATUS_INVALID_RESPONSE: return CKMC_OCSP_ERROR_INVALID_RESPONSE;
    case CKM_API_OCSP_STATUS_REMOTE_ERROR:     return CKMC_OCSP_ERROR_REMOTE;
    case CKM_API_OCSP_STATUS_INTERNAL_ERROR:   return CKMC_OCSP_ERROR_INTERNAL;
    default:                                   return CKMC_OCSP_STATUS_UNKNOWN;
    }
}

int access_to_permission_mask(ckmc_access_right_e ar, int & permissionMask)
{
    switch (ar) {
        case CKMC_AR_READ:
            permissionMask = CKMC_PERMISSION_READ;
            break;

        case CKMC_AR_READ_REMOVE:
            permissionMask = CKMC_PERMISSION_READ | CKMC_PERMISSION_REMOVE;
            break;

        default:
            return CKMC_ERROR_INVALID_PARAMETER;
    }
    return CKMC_ERROR_NONE;
}
