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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <sstream>
#include <fstream>

#include <dpl/log/log.h>

#include <file-system.h>

namespace {

static const std::string CKM_DATA_PATH = "/opt/data/ckm/";
static const std::string CKM_KEY_PREFIX = "key-";
static const std::string CKM_DB_KEY_PREFIX = "db-key-";
static const std::string CKM_DB_PREFIX = "db-";

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

RawBuffer FileSystem::loadFile(const std::string &path) const {
    std::ifstream is(path);

    if (is.fail())
        return RawBuffer();

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

bool FileSystem::saveFile(const std::string &path, const RawBuffer &buffer) const {
    std::ofstream os(path, std::ios::out | std::ofstream::binary);
    std::copy(buffer.begin(), buffer.end(), std::ostreambuf_iterator<char>(os));
    return !os.fail();
}

bool FileSystem::saveDKEK(const RawBuffer &buffer) const {
    return saveFile(getDKEKPath(), buffer);
}

bool FileSystem::saveDBDEK(const RawBuffer &buffer) const {
    return saveFile(getDBDEKPath(), buffer);
}

int FileSystem::init() {
    errno = 0;
    if ((mkdir(CKM_DATA_PATH.c_str(), 0700)) && (errno != EEXIST)) {
        int err = errno;
        LogError("Error in mkdir. Data directory could not be created. Errno: "
            << err << " (" << strerror(err) << ")");
        return -1; // TODO set up some error code
    }
    return 0;
}

int FileSystem::removeUserData() const {
    int err, retCode = 0;

    if (unlink(getDBPath().c_str())) {
        retCode = -1;
        err = errno;
        LogError("Error in unlink user database: " << getDBPath()
            << "Errno: " << errno << " " << strerror(err));
    }

    if (unlink(getDKEKPath().c_str())) {
        retCode = -1;
        err = errno;
        LogError("Error in unlink user DKEK: " << getDKEKPath()
            << "Errno: " << errno << " " << strerror(err));
    }

    if (unlink(getDBDEKPath().c_str())) {
        retCode = -1;
        err = errno;
        LogError("Error in unlink user DBDEK: " << getDBDEKPath()
            << "Errno: " << errno << " " << strerror(err));
    }

    return retCode;
}

} // namespace CKM

