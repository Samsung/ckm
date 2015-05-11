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
 * @file        access-control.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       DB access control layer.
 */
#pragma once

#include <string>
#include <ckm/ckm-type.h>
#include <ckm/ckm-raw-buffer.h>
#include <db-row.h>
#include <permission.h>
#include <generic-socket-manager.h>

namespace CKM {

class AccessControl
{
public:
    /**
     * return true if client uid is from the system services uid space
     */
    bool isSystemService(const uid_t uid) const;
    bool isSystemService(const CKM::Credentials &cred) const;

    /**
     * check if given data can be saved by current accessor
     * @return CKM_API_SUCCESS if access is allowed, otherwise negative error code
     */
    int canSave(const CKM::Credentials &accessorCred,
                const Label & ownerLabel) const;

    /**
     * check if given label can be modified by accessor
     * @return CKM_API_SUCCESS if access is allowed, otherwise negative error code
     */
    int canModify(const CKM::Credentials &accessorCred,
                  const Label & ownerLabel) const;

    /**
     * check if given row can be read (for internal use)
     * @return CKM_API_SUCCESS if access is allowed, otherwise negative error code
     */
    int canRead(const CKM::Credentials &accessorCred,
                const PermissionForLabel & permissionLabel) const;

    /**
     * check if given row can be exported (data provided to the client)
     * @return CKM_API_SUCCESS if access is allowed, otherwise negative error code
     */
    int canExport(const CKM::Credentials &accessorCred,
                  const DB::Row & row,
                  const PermissionForLabel & permissionLabel) const;

    /**
     * check if given accessor can delete ownerLabel's items.
     * @return CKM_API_SUCCESS if access is allowed, otherwise negative error code
     */
    int canDelete(const CKM::Credentials &accessorCred,
                  const PermissionForLabel & permissionLabel) const;

    void updateCCMode();
    bool isCCMode() const;
private:
    bool m_ccMode;
};

} // namespace CKM
