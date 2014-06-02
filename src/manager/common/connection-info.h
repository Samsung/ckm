/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        connection-info.h
 * @author      Lukasz Kostyra (l.kostyra@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Definition of ConnectionInfo structure and ConnectionInfoMap type.
 */

#ifndef _CONNECTION_INFO_H_
#define _CONNECTION_INFO_H_

#include <map>
#include <generic-socket-manager.h>
#include <message-buffer.h>

namespace CKM
{
    struct Credentials {
        std::string realUser;
        std::string realSmackLabel;
    };

    struct ConnectionInfo {
        InterfaceID interfaceID;
        MessageBuffer buffer;
        Credentials credentials;
    };

    typedef std::map<int, ConnectionInfo> ConnectionInfoMap;
} //namespace CKM

#endif //_CONNECTION_INFO_H_
