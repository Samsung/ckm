/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        abstract_log_provider.cpp
 * @author      Pawel Sikorski (p.sikorski@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of abstract log provider
 */
#include <stddef.h>
#include <dpl/log/abstract_log_provider.h>
#include <cstring>

#define UNUSED __attribute__((unused))

namespace CKM {
namespace Log {

void AbstractLogProvider::SetTag(const char *tag UNUSED) {}

const char *AbstractLogProvider::LocateSourceFileName(const char *filename)
{
    const char *ptr = strrchr(filename, '/');
    return ptr != NULL ? ptr + 1 : filename;
}
}
}
