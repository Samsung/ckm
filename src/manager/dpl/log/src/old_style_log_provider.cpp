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
#include <sys/time.h>
#include <unistd.h>
#include <dlog.h>

namespace CentralKeyManager {
namespace Log {
namespace // anonymous
{
using namespace CentralKeyManager::Colors::Text;
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
} // namespace anonymous

std::string OldStyleLogProvider::FormatMessage(const char *message,
                                               const char *filename,
                                               int line,
                                               const char *function)
{
    std::ostringstream val;

    val << std::string("[") << GetFormattedTime() << std::string("] [") <<
    static_cast<unsigned long>(pthread_self()) << "/" <<
    static_cast<int>(getpid()) << std::string("] [") <<
    LocateSourceFileName(filename) << std::string(":") << line <<
    std::string("] ") << function << std::string("(): ") << message;

    return val.str();
}

OldStyleLogProvider::OldStyleLogProvider(bool showDebug,
                                         bool showInfo,
                                         bool showWarning,
                                         bool showError,
                                         bool showPedantic) :
    m_showDebug(showDebug),
    m_showInfo(showInfo),
    m_showWarning(showWarning),
    m_showError(showError),
    m_showPedantic(showPedantic),
    m_printStdErr(false)
{}

OldStyleLogProvider::OldStyleLogProvider(bool showDebug,
                                         bool showInfo,
                                         bool showWarning,
                                         bool showError,
                                         bool showPedantic,
                                         bool printStdErr) :
    m_showDebug(showDebug),
    m_showInfo(showInfo),
    m_showWarning(showWarning),
    m_showError(showError),
    m_showPedantic(showPedantic),
    m_printStdErr(printStdErr)
{}

void OldStyleLogProvider::Debug(const char *message,
                                const char *filename,
                                int line,
                                const char *function)
{
    if (m_showDebug) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", DEBUG_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), DEBUG_END);
        } else {
            fprintf(stdout, "%s%s%s\n", DEBUG_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), DEBUG_END);
        }
    }
}

void OldStyleLogProvider::Info(const char *message,
                               const char *filename,
                               int line,
                               const char *function)
{
    if (m_showInfo) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", INFO_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), INFO_END);
        } else {
            fprintf(stdout, "%s%s%s\n", INFO_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), INFO_END);
        }
    }
}

void OldStyleLogProvider::Warning(const char *message,
                                  const char *filename,
                                  int line,
                                  const char *function)
{
    if (m_showWarning) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", WARNING_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), WARNING_END);
        } else {
            fprintf(stdout, "%s%s%s\n", WARNING_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), WARNING_END);
        }
    }
}

void OldStyleLogProvider::Error(const char *message,
                                const char *filename,
                                int line,
                                const char *function)
{
    if (m_showError) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", ERROR_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), ERROR_END);
        } else {
            fprintf(stdout, "%s%s%s\n", ERROR_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), ERROR_END);
        }
    }
}

void OldStyleLogProvider::Pedantic(const char *message,
                                   const char *filename,
                                   int line,
                                   const char *function)
{
    if (m_showPedantic) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", PEDANTIC_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), PEDANTIC_END);
        } else {
            fprintf(stdout, "%s%s%s\n", PEDANTIC_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), PEDANTIC_END);
        }
    }
}

void OldStyleLogProvider::SecureDebug(const char *message,
                                const char *filename,
                                int line,
                                const char *function)
{
#ifdef _SECURE_LOG
    if (m_showDebug) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", DEBUG_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), DEBUG_END);
        } else {
            fprintf(stdout, "%s%s%s\n", DEBUG_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), DEBUG_END);
        }
    }
#else
    (void)message;
    (void)filename;
    (void)line;
    (void)function;
#endif
}

void OldStyleLogProvider::SecureInfo(const char *message,
                               const char *filename,
                               int line,
                               const char *function)
{
#ifdef _SECURE_LOG
    if (m_showInfo) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", INFO_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), INFO_END);
        } else {
            fprintf(stdout, "%s%s%s\n", INFO_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), INFO_END);
        }
    }
#else
    (void)message;
    (void)filename;
    (void)line;
    (void)function;
#endif
}

void OldStyleLogProvider::SecureWarning(const char *message,
                                  const char *filename,
                                  int line,
                                  const char *function)
{
#ifdef _SECURE_LOG
    if (m_showWarning) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", WARNING_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), WARNING_END);
        } else {
            fprintf(stdout, "%s%s%s\n", WARNING_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), WARNING_END);
        }
    }
#else
    (void)message;
    (void)filename;
    (void)line;
    (void)function;
#endif
}

void OldStyleLogProvider::SecureError(const char *message,
                                const char *filename,
                                int line,
                                const char *function)
{
#ifdef _SECURE_LOG
    if (m_showError) {
        if (m_printStdErr) {
            fprintf(stderr, "%s%s%s\n", ERROR_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), ERROR_END);
        } else {
            fprintf(stdout, "%s%s%s\n", ERROR_BEGIN,
                    FormatMessage(message, filename, line,
                        function).c_str(), ERROR_END);
        }
    }
#else
    (void)message;
    (void)filename;
    (void)line;
    (void)function;
#endif
}

}
} // namespace CentralKeyManager
