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
 * @file        access-control.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       DB access control layer implementation.
 */
#include <vconf/vconf.h>
#include <access-control.h>
#include <dpl/log/log.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>
#include <openssl/crypto.h>

#ifndef VCONFKEY_SECURITY_MDPP_STATE
#define VCONFKEY_SECURITY_MDPP_STATE   "file/security_mdpp/security_mdpp_state"
#endif

namespace {
const char* const MDPP_MODE_ENFORCING = "Enforcing";
const char* const MDPP_MODE_ENABLED = "Enabled";
const char* const MDPP_MODE_DISABLED = "Disabled";
} // anonymous namespace

namespace CKM {

void AccessControl::updateCCMode() {
    int fipsModeStatus = 0;
    int rc = 0;
    bool newMode;

    char *mdppState = vconf_get_str(VCONFKEY_SECURITY_MDPP_STATE);
    newMode = ( mdppState && (!strcmp(mdppState, MDPP_MODE_ENABLED) ||
                              !strcmp(mdppState, MDPP_MODE_ENFORCING) ||
                              !strcmp(mdppState, MDPP_MODE_DISABLED)));
    if (newMode == m_ccMode)
        return;

    m_ccMode = newMode;

    fipsModeStatus = FIPS_mode();

    if(m_ccMode) {
        if(fipsModeStatus == 0) { // If FIPS mode off
            rc = FIPS_mode_set(1); // Change FIPS_mode from off to on
            if(rc == 0) {
                LogError("Error in FIPS_mode_set function");
            }
        }
    } else {
        if(fipsModeStatus == 1) { // If FIPS mode on
            rc = FIPS_mode_set(0); // Change FIPS_mode from on to off
            if(rc == 0) {
                LogError("Error in FIPS_mode_set function");
            }
        }
    }
}

bool AccessControl::isCCMode() const
{
    return m_ccMode;
}


int AccessControl::canRead(
        const DBRow & row,
        const PermissionForLabel & permissionLabel) const
{
    // owner can do everything by default
    if (row.ownerLabel == permissionLabel.accessorLabel)
        return CKM_API_SUCCESS;

    switch(permissionLabel.permissions)
    {
        case Permission::READ:
        case Permission::READ_REMOVE:
            return CKM_API_SUCCESS;

        default:
            return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
    }
}

int AccessControl::canExport(
        const DBRow & row,
        const PermissionForLabel & permissionLabel) const
{
    int ec;
    if(CKM_API_SUCCESS != (ec = canRead(row, permissionLabel)))
        return ec;

    // check if can export
    if(row.exportable == 0)
        return CKM_API_ERROR_NOT_EXPORTABLE;

    // prevent extracting private keys during cc-mode on
    if( isCCMode() )
    {
        switch(row.dataType)
        {
            case DBDataType::KEY_RSA_PRIVATE:
            case DBDataType::KEY_ECDSA_PRIVATE:
            case DBDataType::KEY_DSA_PRIVATE:
                return CKM_API_ERROR_BAD_REQUEST;

            default:
                break;
        }
    }

    return CKM_API_SUCCESS;
}

int AccessControl::canDelete(
        const Label & ownerLabel,
        const PermissionForLabel & permissionLabel) const
{
    // owner can do everything by default
    if (ownerLabel == permissionLabel.accessorLabel)
        return CKM_API_SUCCESS;

    switch(permissionLabel.permissions)
    {
        case Permission::READ:
            return CKM_API_ERROR_ACCESS_DENIED;

        case Permission::READ_REMOVE:
            return CKM_API_SUCCESS;

        default:
            return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
    }
}



} // namespace CKM
