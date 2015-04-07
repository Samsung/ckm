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
 * @file        FileSystem.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Sample service implementation.
 */
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include <cstdlib>
#include <string>
#include <sstream>
#include <fstream>
#include <memory>
#include <stdexcept>

#include <dpl/errno_string.h>
#include <dpl/fstream_accessors.h>
#include <dpl/log/log.h>

#include <file-system.h>

namespace {

const std::string CKM_DATA_PATH = "/opt/data/ckm/";
const std::string CKM_KEY_PREFIX = "key-";
const std::string CKM_DB_KEY_PREFIX = "db-key-";
const std::string CKM_DB_PREFIX = "db-";
const std::string CKM_REMOVED_APP_PREFIX = "removed-app-";
const std::string CKM_LOCK_FILE = "/var/run/key-manager.pid";

} // namespace anonymous

namespace CKM {

FileSystem::FileSystem(uid_t uid)
  : m_uid(uid)
{}

std::string FileSystem::getDBPath() const
{
    std::stringstream ss;
    ss << CKM_DATA_PATH << CKM_DB_PREFIX << m_uid;
    return ss.str();
}

std::string FileSystem::getDKEKPath() const {
    std::stringstream ss;
    ss << CKM_DATA_PATH << CKM_KEY_PREFIX << m_uid;
    return ss.str();
}

std::string FileSystem::getDBDEKPath() const {
    std::stringstream ss;
    ss << CKM_DATA_PATH << CKM_DB_KEY_PREFIX << m_uid;
    return ss.str();
}

std::string FileSystem::getRemovedAppsPath() const {
    std::stringstream ss;
    ss << CKM_DATA_PATH << CKM_REMOVED_APP_PREFIX << m_uid;
    return ss.str();
}

RawBuffer FileSystem::loadFile(const std::string &path) const {
    std::ifstream is(path);

    if (is.fail() && ENOENT == errno)
        return RawBuffer();

    if (is.fail()) {
        auto description = GetErrnoString(errno);
        LogError("Error opening file: " << path << " Reason: " << description);
        ThrowMsg(Exception::OpenFailed,
                 "Error opening file: " << path << " Reason: " << description);
    }

    std::istreambuf_iterator<char> begin(is),end;
    std::vector<char> buff(begin,end); // This trick does not work with boost vector

    RawBuffer buffer(buff.size());
    memcpy(buffer.data(), buff.data(), buff.size());
    return buffer;
}

RawBuffer FileSystem::getDKEK() const
{
    return loadFile(getDKEKPath());
}

RawBuffer FileSystem::getDBDEK() const
{
    return loadFile(getDBDEKPath());
}

void FileSystem::saveFile(const std::string &path, const RawBuffer &buffer) const {
    std::ofstream os(path, std::ios::out | std::ofstream::binary | std::ofstream::trunc);
    std::copy(buffer.begin(), buffer.end(), std::ostreambuf_iterator<char>(os));

    // Prevent desynchronization in batter remove test.
    os.flush();
    fsync(FstreamAccessors<std::ofstream>::GetFd(os)); // flush kernel space buffer
    os.close();

    if (os.fail())
        ThrowMsg(Exception::SaveFailed, "Failed to save file: " << path);
}

void FileSystem::saveDKEK(const RawBuffer &buffer) const {
    saveFile(getDKEKPath(), buffer);
}

void FileSystem::saveDBDEK(const RawBuffer &buffer) const {
    saveFile(getDBDEKPath(), buffer);
}

void FileSystem::addRemovedApp(const std::string &smackLabel) const
{
    std::ofstream outfile;
    outfile.open(getRemovedAppsPath(), std::ios_base::app);
    outfile << smackLabel << std::endl;
    outfile.close();
    if (outfile.fail()) {
        auto desc = GetErrnoString(errno);
        LogError("Could not update file: " << getRemovedAppsPath() << " Reason: " << desc);
        ThrowMsg(Exception::SaveFailed,
                 "Could not update file: " << getRemovedAppsPath() << " Reason: " << desc);
    }
}

AppLabelVector FileSystem::clearRemovedsApps() const
{
    // read the contents
    AppLabelVector removedApps;
    std::string line;
    std::ifstream removedAppsFile(getRemovedAppsPath());
    if (removedAppsFile.is_open()) {
        while (! removedAppsFile.eof() ) {
            getline (removedAppsFile,line);
            if(line.size() > 0)
                removedApps.push_back(line);
        }
        removedAppsFile.close();
    }
    // truncate the contents
    std::ofstream truncateFile;
    truncateFile.open(getRemovedAppsPath(), std::ofstream::out | std::ofstream::trunc);
    truncateFile.close();
    return removedApps;
}

int FileSystem::init() {
    errno = 0;
    if ((mkdir(CKM_DATA_PATH.c_str(), 0700)) && (errno != EEXIST)) {
        int err = errno;
        LogError("Error in mkdir " << CKM_DATA_PATH << ". Reason: " << GetErrnoString(err));
        return -1; // TODO set up some error code
    }
    return 0;
}

UidVector FileSystem::getUIDsFromDBFile() {
    UidVector uids;
    std::unique_ptr<DIR, std::function<int(DIR*)>>
        dirp(::opendir(CKM_DATA_PATH.c_str()), ::closedir);

    if (!dirp.get()) {
        int err = errno;
        LogError("Error in opendir. Data directory could not be read. Error: " << GetErrnoString(err));
        return UidVector();
    }

    size_t len = offsetof(struct dirent, d_name) + pathconf(CKM_DATA_PATH.c_str(), _PC_NAME_MAX) + 1;
    std::unique_ptr<struct dirent, std::function<void(void*)>>
        pEntry(static_cast<struct dirent*>(::malloc(len)), ::free);

    if (!pEntry.get()) {
        LogError("Memory allocation failed.");
        return UidVector();
    }

    struct dirent* pDirEntry = NULL;

    while ( (!readdir_r(dirp.get(), pEntry.get(), &pDirEntry)) && pDirEntry ) {
        // Ignore files with diffrent prefix
        if (strncmp(pDirEntry->d_name, CKM_KEY_PREFIX.c_str(), CKM_KEY_PREFIX.size())) {
            continue;
        }

        // We find database. Let's extract user id.
        try {
            uids.push_back(static_cast<uid_t>(std::stoi((pDirEntry->d_name)+CKM_KEY_PREFIX.size())));
        } catch (const std::invalid_argument) {
            LogError("Error in extracting uid from db file. Error=std::invalid_argument."
                "This will be ignored.File=" << pDirEntry->d_name << "");
        } catch(const std::out_of_range) {
            LogError("Error in extracting uid from db file. Error=std::out_of_range."
                "This will be ignored. File="<< pDirEntry->d_name << "");
        }
    }

    return uids;
}

int FileSystem::removeUserData() const {
    int err, retCode = 0;

    if (unlink(getDBPath().c_str())) {
        retCode = -1;
        err = errno;
        LogError("Error in unlink user database: " << getDBPath()
            << "Errno: " << errno << " " << GetErrnoString(err));
    }

    if (unlink(getDKEKPath().c_str())) {
        retCode = -1;
        err = errno;
        LogError("Error in unlink user DKEK: " << getDKEKPath()
            << "Errno: " << errno << " " << GetErrnoString(err));
    }

    if (unlink(getDBDEKPath().c_str())) {
        retCode = -1;
        err = errno;
        LogError("Error in unlink user DBDEK: " << getDBDEKPath()
            << "Errno: " << errno << " " << GetErrnoString(err));
    }

    if (unlink(getRemovedAppsPath().c_str())) {
        retCode = -1;
        err = errno;
        LogError("Error in unlink user's Removed Apps File: " << getRemovedAppsPath()
            << "Errno: " << errno << " " << GetErrnoString(err));
    }

    return retCode;
}

FileLock FileSystem::lock()
{
    FileLock fl(CKM_LOCK_FILE.c_str());
    return fl;
}

} // namespace CKM

