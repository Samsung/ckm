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
#include <access-control.h>
#include <dpl/log/log.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>
#include <openssl/crypto.h>

#ifdef SECURITY_MDFPP_STATE_ENABLE
#include <vconf/vconf.h>
#endif

#if defined(SECURITY_MDFPP_STATE_ENABLE) && !defined(VCONFKEY_SECURITY_MDPP_STATE)
#define VCONFKEY_SECURITY_MDPP_STATE "file/security_mdpp/security_mdpp_state"
#endif

namespace {
const char* const MDPP_MODE_ENFORCING = "Enforcing";
const char* const MDPP_MODE_ENABLED = "Enabled";
const char* const MDPP_MODE_DISABLED = "Disabled";
const uid_t       SYSTEM_SVC_MAX_UID = (5000 - 1);
} // anonymous namespace

namespace CKM {

void AccessControl::updateCCMode() {
    int fipsModeStatus = 0;
    int rc = 0;
    bool newMode;

#ifdef SECURITY_MDFPP_STATE_ENABLE
    char *mdppState = vconf_get_str(VCONFKEY_SECURITY_MDPP_STATE);
#else
    char *mdppState = NULL;
#endif
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

bool AccessControl::isSystemService(const uid_t uid) const
{
    return uid <= SYSTEM_SVC_MAX_UID;
}

bool AccessControl::isSystemService(const CKM::Credentials &cred) const
{
    return isSystemService(cred.clientUid);
}


int AccessControl::canSave(
        const CKM::Credentials &accessorCred,
        const Label & ownerLabel) const
{
    if(isSystemService(accessorCred))
        return CKM_API_SUCCESS;
    if(ownerLabel != accessorCred.smackLabel)
        return CKM_API_ERROR_ACCESS_DENIED;

    return CKM_API_SUCCESS;
}

int AccessControl::canModify(
        const CKM::Credentials &accessorCred,
        const Label & ownerLabel) const
{
    return canSave(accessorCred, ownerLabel);
}

int AccessControl::canRead(
        const CKM::Credentials &accessorCred,
        const PermissionForLabel & permissionLabel) const
{
    if(isSystemService(accessorCred))
        return CKM_API_SUCCESS;
    if(permissionLabel & Permission::READ)
        return CKM_API_SUCCESS;

    return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
}

int AccessControl::canExport(
        const CKM::Credentials &accessorCred,
        const DB::Row & row,
        const PermissionForLabel & permissionLabel) const
{
    int ec;
    if(CKM_API_SUCCESS != (ec = canRead(accessorCred, permissionLabel)))
        return ec;

    // check if can export
    if(row.exportable == 0)
        return CKM_API_ERROR_NOT_EXPORTABLE;

    // prevent extracting private keys during cc-mode on
    if (isCCMode() && row.dataType.isKeyPrivate())
        return CKM_API_ERROR_BAD_REQUEST;

    return CKM_API_SUCCESS;
}

int AccessControl::canDelete(
        const CKM::Credentials &accessorCred,
        const PermissionForLabel & permissionLabel) const
{
    if(isSystemService(accessorCred))
        return CKM_API_SUCCESS;
    if(permissionLabel & Permission::REMOVE)
        return CKM_API_SUCCESS;
    if(permissionLabel & Permission::READ)
        return CKM_API_ERROR_ACCESS_DENIED;

    return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
}



} // namespace CKM
