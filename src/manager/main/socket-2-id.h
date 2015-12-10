/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file       socket-2-id.h
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once

#include <map>
#include <string>

namespace CKM {

class Socket2Id {
public:
    Socket2Id() {}

    int translate(int sock, std::string &result);
    void resetCache();

    virtual ~Socket2Id() {}

private:
    int getCredentialsFromSocket(int sock, std::string &res);
    int getPkgIdFromSmack(const std::string &smack, std::string &pkgId);

    typedef std::map<std::string, std::string> StringMap;
    StringMap m_stringMap;
};

} // namespace CKM

