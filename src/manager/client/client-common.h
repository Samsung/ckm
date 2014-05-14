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
 * @file        client-common.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of common types
 *              used in Central Key Manager.
 */

#ifndef _KEY_MANAGER_CLIENT_
#define _KEY_MANAGER_CLIENT_

#include <vector>
#include <functional>

#include <message-buffer.h>

#define KEY_MANAGER_API __attribute__((visibility("default")))

extern "C" {
    struct msghdr;
}

namespace CentralKeyManager {

typedef std::vector<unsigned char> RawBuffer;

int sendToServer(char const * const interface, const RawBuffer &send, MessageBuffer &recv);

/*
 * Decorator function that performs frequently repeated exception handling in
 * SS client API functions. Accepts lambda expression as an argument.
 */
int try_catch(const std::function<int()>& func);

} // namespace CentralKeyManager

#endif // _KEY_MANAGER_CLIENT_
