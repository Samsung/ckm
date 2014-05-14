/*
 *  Central Key Manager
 *
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 */

#ifndef CENT_KEY_MNG_UTIL_H
#define CENT_KEY_MNG_UTIL_H

#include <sys/types.h>

namespace CentralKeyManager {

int util_smack_label_is_valid(const char *smack_label);
char *read_exe_path_from_proc(pid_t pid);

} // namespace CentralKeyManager

#endif /*CENT_KEY_MNG_UTIL_H*/
