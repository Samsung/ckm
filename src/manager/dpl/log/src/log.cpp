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
 * @file        log.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of log system
 */
#include <stddef.h>
#include <string.h>

#include <string>
#include <stdexcept>
#include <unordered_map>
#include <cassert>

#include <dpl/log/log.h>
#include <dpl/singleton_safe_impl.h>
#include <dpl/log/old_style_log_provider.h>
#include <dpl/log/dlog_log_provider.h>
#include <dpl/log/journal_log_provider.h>

IMPLEMENT_SAFE_SINGLETON(CKM::Log::LogSystem);

namespace CKM {
namespace Log {
namespace // anonymous
{
/*
 * Set these variables to desired values in /etc/sysconfig/central-key-manager and restart
 * central-key-manager service to use them.
 *
 * Example:
 * CKM_LOG_LEVEL=3
 * CKM_LOG_PROVIDER=JOURNALD
 */
const char * const CKM_LOG_LEVEL =      "CKM_LOG_LEVEL";
const char * const CKM_LOG_PROVIDER =   "CKM_LOG_PROVIDER";

const std::string CONSOLE =     "CONSOLE";
const std::string DLOG =        "DLOG";
const std::string JOURNALD =    "JOURNALD";

typedef AbstractLogProvider*(*provider_fn)();
std::unordered_map<std::string, provider_fn> new_provider = {
#ifdef BUILD_TYPE_DEBUG
        { CONSOLE,  []{ return static_cast<AbstractLogProvider*>(new OldStyleLogProvider()); } },
#endif // BUILD_TYPE_DEBUG
        { DLOG,     []{ return static_cast<AbstractLogProvider*>(new DLOGLogProvider()); } },
        { JOURNALD, []{ return static_cast<AbstractLogProvider*>(new JournalLogProvider()); } }
};

} // namespace anonymous

LogSystem::LogSystem()
{
    SetLogLevel(getenv(CKM_LOG_LEVEL));

    AbstractLogProvider* prv = NULL;
    try {
        prv = new_provider.at(getenv(CKM_LOG_PROVIDER))();
    } catch(const std::exception&) {
        prv = new_provider[DLOG]();
    }
    AddProvider(prv);
}

LogSystem::~LogSystem()
{
    RemoveProviders();
}

void LogSystem::SetTag(const char* tag)
{
    for (auto it : m_providers)
        it->SetTag(tag);
}

void LogSystem::AddProvider(AbstractLogProvider *provider)
{
    m_providers.push_back(provider);
}

void LogSystem::RemoveProvider(AbstractLogProvider *provider)
{
    m_providers.remove(provider);
}

void LogSystem::SelectProvider(const std::string& name)
{
    // let it throw
    provider_fn& prv = new_provider.at(name);

    RemoveProviders();
    AddProvider(prv());
}

void LogSystem::SetLogLevel(const char* level)
{
    try {
        m_level = static_cast<AbstractLogProvider::LogLevel>(std::stoi(level));
    } catch(const std::exception&) {
        m_level = AbstractLogProvider::LogLevel::Debug;
    }

    if (m_level < AbstractLogProvider::LogLevel::None)
        m_level = AbstractLogProvider::LogLevel::None;
    else if (m_level > AbstractLogProvider::LogLevel::Pedantic)
        m_level = AbstractLogProvider::LogLevel::Pedantic;

#ifndef BUILD_TYPE_DEBUG
    if (m_level > AbstractLogProvider::LogLevel::Error)
        m_level = AbstractLogProvider::LogLevel::Error;
#endif // BUILD_TYPE_DEBUG
}

void LogSystem::Log(AbstractLogProvider::LogLevel level,
                    const char *message,
                    const char *filename,
                    int line,
                    const char *function)
{
    for (const auto& it : m_providers )
        it->Log(level, message, filename, line, function);
}

void LogSystem::RemoveProviders()
{
    // Delete all providers
    for (auto it : m_providers)
        delete it;

    m_providers.clear();
}

} // namespace Log
} // namespace CKM
