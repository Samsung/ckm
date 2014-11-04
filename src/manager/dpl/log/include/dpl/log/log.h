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
#include <dpl/noncopyable.h>
#include <dpl/log/abstract_log_provider.h>
#include <sstream>
#include <list>

namespace CKM {
namespace Log {
/**
 * CKM log system
 *
 * To switch logs into old style, export
 * DPL_USE_OLD_STYLE_LOGS before application start
 */
class LogSystem :
    private Noncopyable
{
  private:
    typedef std::list<AbstractLogProvider *> AbstractLogProviderPtrList;
    AbstractLogProviderPtrList m_providers;

    bool m_isLoggingEnabled;

  public:
    bool IsLoggingEnabled() const;
    LogSystem();
    virtual ~LogSystem();

    /**
     * Log debug message
     */
    void Debug(const char *message,
               const char *filename,
               int line,
               const char *function);

    /**
     * Log info message
     */
    void Info(const char *message,
              const char *filename,
              int line,
              const char *function);

    /**
     * Log warning message
     */
    void Warning(const char *message,
                 const char *filename,
                 int line,
                 const char *function);

    /**
     * Log error message
     */
    void Error(const char *message,
               const char *filename,
               int line,
               const char *function);

    /**
     * Log pedantic message
     */
    void Pedantic(const char *message,
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
#define DPL_MACRO_DUMMY_LOGGING(message, function)                         \
    do {                                                                   \
        CKM::Log::NullStream ns;                                \
        ns << message;                                                     \
    } while (0)

#define DPL_MACRO_FOR_LOGGING(message, function)                           \
do                                                                         \
{                                                                          \
    if (CKM::Log::LogSystemSingleton::Instance().IsLoggingEnabled())   \
    {                                                                      \
        std::ostringstream platformLog;                                    \
        platformLog << message;                                            \
        CKM::Log::LogSystemSingleton::Instance().function(      \
            platformLog.str().c_str(),                                     \
            __FILE__, __LINE__, __FUNCTION__);                             \
    }                                                                      \
} while (0)

/* Errors must be always logged. */
#define  LogError(message) DPL_MACRO_FOR_LOGGING(message, Error)

#ifdef BUILD_TYPE_DEBUG
    #define LogDebug(message) DPL_MACRO_FOR_LOGGING(message, Debug)
    #define LogInfo(message) DPL_MACRO_FOR_LOGGING(message, Info)
    #define LogWarning(message) DPL_MACRO_FOR_LOGGING(message, Warning)
    #define LogPedantic(message) DPL_MACRO_FOR_LOGGING(message, Pedantic)
#else
    #define LogDebug(message) DPL_MACRO_DUMMY_LOGGING(message, Debug)
    #define LogInfo(message) DPL_MACRO_DUMMY_LOGGING(message, Info)
    #define LogWarning(message) DPL_MACRO_DUMMY_LOGGING(message, Warning)
    #define LogPedantic(message) DPL_MACRO_DUMMY_LOGGING(message, Pedantic)
#endif // BUILD_TYPE_DEBUG

#endif // CENT_KEY_LOG_H
