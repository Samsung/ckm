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
 * @file        dlog_log_provider.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of DLOG log provider
 */
#include <stddef.h>
#include <dpl/log/dlog_log_provider.h>
#include <cstring>
#include <sstream>
#include <dlog.h>

#define UNUSED __attribute__((unused))

namespace CKM {
namespace Log {
std::string DLOGLogProvider::FormatMessage(const char *message,
                                           const char *filename,
                                           int line,
                                           const char *function)
{
    std::ostringstream val;

    val << std::string("[") <<
    LocateSourceFileName(filename) << std::string(":") << line <<
    std::string("] ") << function << std::string("(): ") << message;

    return val.str();
}

DLOGLogProvider::DLOGLogProvider()
{}

DLOGLogProvider::~DLOGLogProvider()
{}

void DLOGLogProvider::SetTag(const char *tag)
{
    size_t size = strlen(tag)+1;
    char *buff = new (std::nothrow) char[size];
    if (buff)
        memcpy(buff, tag, size);
    m_tag.reset(buff);
}

void DLOGLogProvider::Debug(const char *message,
                            const char *filename,
                            int line,
                            const char *function)
{
    SLOG(LOG_DEBUG, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

void DLOGLogProvider::Info(const char *message,
                           const char *filename,
                           int line,
                           const char *function)
{
    SLOG(LOG_INFO, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

void DLOGLogProvider::Warning(const char *message,
                              const char *filename,
                              int line,
                              const char *function)
{
    SLOG(LOG_WARN, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

void DLOGLogProvider::Error(const char *message,
                            const char *filename,
                            int line,
                            const char *function)
{
    SLOG(LOG_ERROR, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

void DLOGLogProvider::Pedantic(const char *message,
                               const char *filename,
                               int line,
                               const char *function)
{
    SLOG(LOG_DEBUG, "CKM", "%s", FormatMessage(message,
                                              filename,
                                              line,
                                              function).c_str());
}

void DLOGLogProvider::SecureDebug(const char *message UNUSED,
                            const char *filename UNUSED,
                            int line UNUSED,
                            const char *function UNUSED)
{
    SECURE_SLOG(LOG_DEBUG, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

void DLOGLogProvider::SecureInfo(const char *message UNUSED,
                           const char *filename UNUSED,
                           int line UNUSED,
                           const char *function UNUSED)
{
    SECURE_SLOG(LOG_INFO, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

void DLOGLogProvider::SecureWarning(const char *message UNUSED,
                              const char *filename UNUSED,
                              int line UNUSED,
                              const char *function UNUSED)
{
    SECURE_SLOG(LOG_WARN, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

void DLOGLogProvider::SecureError(const char *message UNUSED,
                            const char *filename UNUSED,
                            int line UNUSED,
                            const char *function UNUSED)
{
    SECURE_SLOG(LOG_ERROR, m_tag.get(), "%s",
        FormatMessage(message, filename, line, function).c_str());
}

} // nemespace Log
} // namespace CKM
