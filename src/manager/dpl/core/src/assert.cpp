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
 * @file        assert.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of assert
 */
#include <stddef.h>
#include <dpl/assert.h>
#include <dpl/colors.h>
#include <dpl/log/log.h>
#include <dpl/exception.h>
#include <cstdlib>

namespace CentralKeyManager {
void AssertProc(const char *condition,
                const char *file,
                int line,
                const char *function)
{
#define INTERNAL_LOG(message)                                          \
    do                                                                 \
    {                                                                  \
        std::ostringstream platformLog;                                \
        platformLog << message;                                        \
        CentralKeyManager::Log::LogSystemSingleton::Instance().Pedantic(             \
            platformLog.str().c_str(),                                 \
            __FILE__, __LINE__, __FUNCTION__);                         \
    } \
    while (0)

    // Try to log failed assertion to log system
    Try
    {
        INTERNAL_LOG(
            "################################################################################");
        INTERNAL_LOG(
            "###                          CentralKeyManager assertion failed!                           ###");
        INTERNAL_LOG(
            "################################################################################");
        INTERNAL_LOG("### Condition: " << condition);
        INTERNAL_LOG("### File: " << file);
        INTERNAL_LOG("### Line: " << line);
        INTERNAL_LOG("### Function: " << function);
        INTERNAL_LOG(
            "################################################################################");
    } catch (Exception) {
        // Just ignore possible double errors
    }

    // Fail with c-library abort
    abort();
}
} // namespace CentralKeyManager
