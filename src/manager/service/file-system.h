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
 * @file        FileSystem.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#pragma once

#include <ckm/ckm-type.h>
#include <string>
#include <file-lock.h>

namespace CKM {

typedef std::vector<std::string> AppLabelVector;
typedef std::vector<uid_t> UidVector;

class FileSystem {
public:
    FileSystem(uid_t uid);

    std::string getDBPath() const;

    // Domain Key Encryption Key
    RawBuffer getDKEK() const;
    RawBuffer getDKEKBackup() const;
    bool saveDKEK(const RawBuffer &buffer) const;

    // Functions required in "password change transaction"
    bool saveDKEKBackup(const RawBuffer &buffer) const;
    bool restoreDKEK() const; // delete DKEK and move DKEKBackup -> DKEK
    bool removeDKEKBackup() const;  // delete DKEKBackup

    // Database Data Encryption Key
    RawBuffer getDBDEK() const;
    bool saveDBDEK(const RawBuffer &buffer) const;

    // Remove all ckm data related to user
    int removeUserData() const;

    bool addRemovedApp(const std::string &smackLabel) const;
    AppLabelVector clearRemovedsApps() const;

    static int init();
    static UidVector getUIDsFromDBFile();
    static FileLock lock();

    virtual ~FileSystem(){}
protected:
    std::string getDKEKPath() const;
    std::string getDKEKBackupPath() const;
    std::string getDBDEKPath() const;
    RawBuffer loadFile(const std::string &path) const;
    bool saveFile(const std::string &path, const RawBuffer &buffer) const;
    std::string getRemovedAppsPath() const;

    uid_t m_uid;
};

} // namespace CKM

