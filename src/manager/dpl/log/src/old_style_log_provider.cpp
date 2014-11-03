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
 * @file        old_style_log_provider.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of old style log provider
 */
#include <stddef.h>
#include <dpl/log/old_style_log_provider.h>
#include <dpl/colors.h>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <map>
#include <stdexcept>
#include <sys/time.h>
#include <unistd.h>
#include <dlog.h>

namespace CKM {
namespace Log {
namespace // anonymous
{
using namespace CKM::Colors::Text;
const char *DEBUG_BEGIN = GREEN_BEGIN;
const char *DEBUG_END = GREEN_END;
const char *INFO_BEGIN = CYAN_BEGIN;
const char *INFO_END = CYAN_END;
const char *ERROR_BEGIN = RED_BEGIN;
const char *ERROR_END = RED_END;
const char *WARNING_BEGIN = BOLD_GOLD_BEGIN;
const char *WARNING_END = BOLD_GOLD_END;
const char *PEDANTIC_BEGIN = PURPLE_BEGIN;
const char *PEDANTIC_END = PURPLE_END;

std::string GetFormattedTime()
{
    timeval tv;
    tm localNowTime;

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &localNowTime);

    char format[64];
    snprintf(format,
             sizeof(format),
             "%02i:%02i:%02i.%03i",
             localNowTime.tm_hour,
             localNowTime.tm_min,
             localNowTime.tm_sec,
             static_cast<int>(tv.tv_usec / 1000));
    return format;
}

struct ColorMark {
    const char* const begin;
    const char* const end;
};

std::map<AbstractLogProvider::LogLevel, ColorMark> consoleLevel = {
        { AbstractLogProvider::LogLevel::Error,     {ERROR_BEGIN,       ERROR_END} },
        { AbstractLogProvider::LogLevel::Warning,   {WARNING_BEGIN,     WARNING_END} },
        { AbstractLogProvider::LogLevel::Info,      {INFO_BEGIN,        INFO_END} },
        { AbstractLogProvider::LogLevel::Debug,     {DEBUG_BEGIN,       DEBUG_END} },
        { AbstractLogProvider::LogLevel::Pedantic,  {PEDANTIC_BEGIN,    PEDANTIC_END} }
};

} // namespace anonymous

OldStyleLogProvider::OldStyleLogProvider()
{}

void OldStyleLogProvider::Log(AbstractLogProvider::LogLevel level,
                              const char *message,
                              const char *fileName,
                              int line,
                              const char *function) const
{
    try {
        const struct ColorMark& mark = consoleLevel.at(level);

        std::ostringstream val;
        val << mark.begin << std::string("[") << GetFormattedTime() << std::string("] [") <<
               static_cast<unsigned long>(pthread_self()) << "/" << static_cast<int>(getpid()) <<
               std::string("] [") << LocateSourceFileName(fileName) << std::string(":") << line <<
               std::string("] ") << function << std::string("(): ") << message << mark.end;
        fprintf(stdout, "%s\n", val.str().c_str());
    } catch (const std::out_of_range&) {
        fprintf(stdout, "Unsupported log level: %d\n", level);
    }

}

}
} // namespace CKM
