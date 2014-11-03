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
 * @file        exception.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation of exception system
 */
#include <stddef.h>
#include <dpl/exception.h>
#include <dpl/log/log.h>
#include <cstdio>

namespace CKM {
Exception* Exception::m_lastException = NULL;
unsigned int Exception::m_exceptionCount = 0;
void (*Exception::m_terminateHandler)() = NULL;

void LogUnhandledException(const std::string &str)
{
    // Logging to console
    printf("%s\n", str.c_str());

    // Logging to dlog
    LogPedantic(str);
}

void LogUnhandledException(const std::string &str,
                           const char *filename,
                           int line,
                           const char *function)
{
    // Logging to console
    std::ostringstream msg;
    msg << "\033[1;5;31m\n=== [" << filename << ":" << line << "] " <<
    function << " ===\033[m";
    msg << str;
    printf("%s\n", msg.str().c_str());

    // Logging to dlog
    CKM::Log::LogSystemSingleton::Instance().Log(CKM::Log::AbstractLogProvider::LogLevel::Error,
                                                 str.c_str(),
                                                 filename,
                                                 line,
                                                 function);
}
} // namespace CKM
