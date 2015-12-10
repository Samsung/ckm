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
#include <stdexcept>
#include <map>
#include <dlog.h>

namespace CKM {
namespace Log {

namespace {
typedef void (*dlogMacro)(const char*, const char*);

// I can't map LOG_ values because SLOG uses token concatenation
void error(const char* tag, const char* msg)
{
    SLOG(LOG_ERROR, tag, "%s", msg);
}
void warning(const char* tag, const char* msg)
{
    SLOG(LOG_WARN, tag, "%s", msg);
}
void info(const char* tag, const char* msg)
{
    SLOG(LOG_INFO, tag, "%s", msg);
}
void debug(const char* tag, const char* msg)
{
    SLOG(LOG_DEBUG, tag, "%s", msg);
}
void pedantic(const char* tag, const char* msg)
{
    SLOG(LOG_VERBOSE, tag, "%s", msg);
}
std::map<AbstractLogProvider::LogLevel, dlogMacro> dlogMacros = {
        // [](const char* tag, const char* msg) { SLOG(LOG_ERROR, tag, "%s", msg); } won't compile
        { AbstractLogProvider::LogLevel::Error,     error },
        { AbstractLogProvider::LogLevel::Warning,   warning },
        { AbstractLogProvider::LogLevel::Info,      info },
        { AbstractLogProvider::LogLevel::Debug,     debug},
        { AbstractLogProvider::LogLevel::Pedantic,  pedantic}
};

} // namespace anonymous


DLOGLogProvider::DLOGLogProvider()
{
}

DLOGLogProvider::~DLOGLogProvider()
{
}

void DLOGLogProvider::SetTag(const char *tag)
{
    size_t size = strlen(tag)+1;
    char *buff = new (std::nothrow) char[size];
    if (buff)
        memcpy(buff, tag, size);
    m_tag.reset(buff);
}

void DLOGLogProvider::Log(AbstractLogProvider::LogLevel level,
                          const char *message,
                          const char *fileName,
                          int line,
                          const char *function) const
{
    std::ostringstream val;
    val << std::string("[") << LocateSourceFileName(fileName) << std::string(":") << line <<
           std::string("] ") << function << std::string("(): ") << message;

    try {
        dlogMacros.at(level)(m_tag.get(), val.str().c_str());
    } catch (const std::out_of_range&) {
        SLOG(LOG_ERROR, m_tag.get(), "Unsupported log level: %d", level);
    }
}

} // nemespace Log
} // namespace CKM
