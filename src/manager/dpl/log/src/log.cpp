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
#include <dpl/singleton_impl.h>
#include <dpl/log/old_style_log_provider.h>
#include <dpl/log/dlog_log_provider.h>
#include <dpl/log/journal_log_provider.h>

IMPLEMENT_SINGLETON(CKM::Log::LogSystem)

namespace CKM {
namespace Log {
namespace // anonymous
{
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
    try {
        m_level = static_cast<AbstractLogProvider::LogLevel>(std::stoi(getenv(CKM_LOG_LEVEL)));
    } catch(const std::exception&) {
        m_level = AbstractLogProvider::LogLevel::Debug;
    }
#ifndef BUILD_TYPE_DEBUG
    if (m_level > AbstractLogProvider::LogLevel::Error)
        m_level = AbstractLogProvider::LogLevel::Error;
#endif // BUILD_TYPE_DEBUG

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
    // Delete all providers
    for (AbstractLogProviderPtrList::iterator iterator = m_providers.begin();
         iterator != m_providers.end();
         ++iterator)
    {
        delete *iterator;
    }

    m_providers.clear();
}

void LogSystem::SetTag(const char* tag)
{
    for (AbstractLogProviderPtrList::iterator iterator = m_providers.begin();
         iterator != m_providers.end();
         ++iterator)
    {
        (*iterator)->SetTag(tag);
    }
}

void LogSystem::AddProvider(AbstractLogProvider *provider)
{
    m_providers.push_back(provider);
}

void LogSystem::RemoveProvider(AbstractLogProvider *provider)
{
    m_providers.remove(provider);
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

}
} // namespace CKM
