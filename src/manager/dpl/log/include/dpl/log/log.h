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
 * @file        log.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of log system
 */
#ifndef CENT_KEY_LOG_H
#define CENT_KEY_LOG_H

#include <dpl/singleton.h>
#include <dpl/log/abstract_log_provider.h>
#include <sstream>
#include <list>
#include <unordered_map>
#include <string>

#include <noncopyable.h>
#include <symbol-visibility.h>

namespace CKM {
namespace Log {

/**
 * CKM log system
 */
class COMMON_API LogSystem
{
  public:
    NONCOPYABLE(LogSystem)

    LogSystem();
    virtual ~LogSystem();

    AbstractLogProvider::LogLevel GetLogLevel() const { return m_level; }

    void Log(AbstractLogProvider::LogLevel level,
             const char *message,
             const char *filename,
             int line,
             const char *function);

    /**
     * Set default's DLOG provider Tag
     */
    void SetTag(const char *tag);

    /**
     * Add abstract provider to providers list
     *
     * @notice Ownership is transfered to LogSystem and deleted upon exit
     */
    void AddProvider(AbstractLogProvider *provider);

    /**
     * Remove abstract provider from providers list
     */
    void RemoveProvider(AbstractLogProvider *provider);

    /**
     * Selects given provider by name (overwrites environment setting)
     *
     * Throws std::out_of_range exception if not found.
     */
    void SelectProvider(const std::string& name);

    /**
     * Sets log level (overwrites environment settings)
     */
    void SetLogLevel(const char* level);

  private:
    void RemoveProviders();

    typedef std::list<AbstractLogProvider *> AbstractLogProviderPtrList;
    AbstractLogProviderPtrList m_providers;
    AbstractLogProvider::LogLevel m_level;

    typedef AbstractLogProvider*(*ProviderFn)();
    /*
     * It cannot be global as it is used in library constructor and we can't be sure which
     * constructor is called first: library's or new_provider's.
     */
    std::unordered_map<std::string, ProviderFn> m_providerCtor;
};

/*
 * Replacement low overhead null logging class
 */
class NullStream
{
  public:
    NullStream() {}

    template <typename T>
    NullStream& operator<<(const T&)
    {
        return *this;
    }
};

/**
 * Log system singleton
 */
typedef Singleton<LogSystem> LogSystemSingleton;
}
} // namespace CKM

//
// Log support
//
//

/* avoid warnings about unused variables */
#define DPL_MACRO_DUMMY_LOGGING(message, level)                                 \
    do {                                                                        \
        CKM::Log::NullStream ns;                                                \
        ns << message;                                                          \
    } while (0)

#define DPL_MACRO_FOR_LOGGING(message, level)                                   \
do                                                                              \
{                                                                               \
    if (level > CKM::Log::AbstractLogProvider::LogLevel::None &&                \
        CKM::Log::LogSystemSingleton::Instance().GetLogLevel() >= level)        \
    {                                                                           \
        std::ostringstream platformLog;                                         \
        platformLog << message;                                                 \
        CKM::Log::LogSystemSingleton::Instance().Log(level,                     \
                                                     platformLog.str().c_str(), \
                                                     __FILE__,                  \
                                                     __LINE__,                  \
                                                     __FUNCTION__);             \
    }                                                                           \
} while (0)

#define DPL_MACRO_FOR_LOGGING_POSITION(message, level, file, line, function)    \
do                                                                              \
{                                                                               \
    if (level > CKM::Log::AbstractLogProvider::LogLevel::None &&                \
        CKM::Log::LogSystemSingleton::Instance().GetLogLevel() >= level)        \
    {                                                                           \
        std::ostringstream platformLog;                                         \
        platformLog << message;                                                 \
        CKM::Log::LogSystemSingleton::Instance().Log(level,                     \
                                                     platformLog.str().c_str(), \
                                                     file,                      \
                                                     line,                      \
                                                     function);                 \
    }                                                                           \
} while (0)

/* Errors must be always logged. */
#define  LogError(message)          \
    DPL_MACRO_FOR_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Error)
#define  LogErrorPosition(message, file, line, function)          \
    DPL_MACRO_FOR_LOGGING_POSITION(message, CKM::Log::AbstractLogProvider::LogLevel::Error, file, line, function)

#ifdef BUILD_TYPE_DEBUG
    #define LogDebug(message)       \
        DPL_MACRO_FOR_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Debug)
    #define LogInfo(message)        \
        DPL_MACRO_FOR_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Info)
    #define LogWarning(message)     \
        DPL_MACRO_FOR_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Warning)
    #define LogPedantic(message)    \
        DPL_MACRO_FOR_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Pedantic)
    #define LogDebugPosition(message, file, line, function) \
        DPL_MACRO_FOR_LOGGING_POSITION(message, CKM::Log::AbstractLogProvider::LogLevel::Debug, file, line, function)
#else
    #define LogDebug(message)       \
        DPL_MACRO_DUMMY_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Debug)
    #define LogInfo(message)        \
        DPL_MACRO_DUMMY_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Info)
    #define LogWarning(message)     \
        DPL_MACRO_DUMMY_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Warning)
    #define LogPedantic(message)    \
        DPL_MACRO_DUMMY_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Pedantic)
    #define LogDebugPosition(message, file, line, function)                                    \
        do {                                                                                   \
            (void) file; (void) line; (void) function;                                         \
            DPL_MACRO_DUMMY_LOGGING(message, CKM::Log::AbstractLogProvider::LogLevel::Debug);  \
        } while(0)
#endif // BUILD_TYPE_DEBUG

#endif // CENT_KEY_LOG_H
