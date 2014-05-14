/*
 *  key-manager
 *
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

#ifndef _SMACK_CHECK_H_
#define _SMACK_CHECK_H_

namespace CentralKeyManager {

/*
 * A very simple runtime check for SMACK on the platform
 * Returns 1 if SMACK is present, 0 otherwise
 */

int smack_runtime_check(void);

/*
 * A very simple runtime check for SMACK on the platform
 * Returns 1 if SMACK is present, 0 otherwise. If SMACK_ENABLED is not defined
 * It returns 0.
 */
int smack_check(void);

} // namespace CentralKeyManager

#endif // _SMACK_CHECK_H_
