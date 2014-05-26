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
 * @file    exception.h
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version 1.0
 * @brief   Header file for base exception
 */
#ifndef CENT_KEY_EXCEPTION_H
#define CENT_KEY_EXCEPTION_H

#include <string>
#include <cstring>
#include <cstdio>
#include <exception>
#include <cstdlib>
#include <sstream>

namespace CKM {
void LogUnhandledException(const std::string &str);
void LogUnhandledException(const std::string &str,
                           const char *filename,
                           int line,
                           const char *function);
}

namespace CKM {
class Exception
{
  private:
    static unsigned int m_exceptionCount;
    static Exception* m_lastException;
    static void (*m_terminateHandler)();

    static void AddRef(Exception* exception)
    {
        if (!m_exceptionCount) {
            m_terminateHandler = std::set_terminate(&TerminateHandler);
        }

        ++m_exceptionCount;
        m_lastException = exception;
    }

    static void UnRef(Exception* e)
    {
        if (m_lastException == e) {
            m_lastException = NULL;
        }

        --m_exceptionCount;

        if (!m_exceptionCount) {
            std::set_terminate(m_terminateHandler);
            m_terminateHandler = NULL;
        }
    }

    static void TerminateHandler()
    {
        if (m_lastException != NULL) {
            DisplayKnownException(*m_lastException);
            abort();
        } else {
            DisplayUnknownException();
            abort();
        }
    }

    Exception *m_reason;
    std::string m_path;
    std::string m_function;
    int m_line;

  protected:
    std::string m_message;
    std::string m_className;

  public:
    static std::string KnownExceptionToString(const Exception &e)
    {
        std::ostringstream message;
        message <<
        "\033[1;5;31m\n=== Unhandled CKM exception occurred ===\033[m\n\n";
        message << "\033[1;33mException trace:\033[m\n\n";
        message << e.DumpToString();
        message << "\033[1;31m\n=== Will now abort ===\033[m\n";

        return message.str();
    }

    static std::string UnknownExceptionToString()
    {
        std::ostringstream message;
        message <<
        "\033[1;5;31m\n=== Unhandled non-CKM exception occurred ===\033[m\n\n";
        message << "\033[1;31m\n=== Will now abort ===\033[m\n";

        return message.str();
    }

    static void DisplayKnownException(const Exception& e)
    {
        LogUnhandledException(KnownExceptionToString(e).c_str());
    }

    static void DisplayUnknownException()
    {
        LogUnhandledException(UnknownExceptionToString().c_str());
    }

    Exception(const Exception &other)
    {
        // Deep copy
        if (other.m_reason != NULL) {
            m_reason = new Exception(*other.m_reason);
        } else {
            m_reason = NULL;
        }

        m_message = other.m_message;
        m_path = other.m_path;
        m_function = other.m_function;
        m_line = other.m_line;

        m_className = other.m_className;

        AddRef(this);
    }

    const Exception &operator =(const Exception &other)
    {
        if (this == &other) {
            return *this;
        }

        // Deep copy
        if (other.m_reason != NULL) {
            m_reason = new Exception(*other.m_reason);
        } else {
            m_reason = NULL;
        }

        m_message = other.m_message;
        m_path = other.m_path;
        m_function = other.m_function;
        m_line = other.m_line;

        m_className = other.m_className;

        AddRef(this);

        return *this;
    }

    Exception(const char *path,
              const char *function,
              int line,
              const std::string &message) :
        m_reason(NULL),
        m_path(path),
        m_function(function),
        m_line(line),
        m_message(message)
    {
        AddRef(this);
    }

    Exception(const char *path,
              const char *function,
              int line,
              const Exception &reason,
              const std::string &message) :
        m_reason(new Exception(reason)),
        m_path(path),
        m_function(function),
        m_line(line),
        m_message(message)
    {
        AddRef(this);
    }

    virtual ~Exception() throw()
    {
        if (m_reason != NULL) {
            delete m_reason;
            m_reason = NULL;
        }

        UnRef(this);
    }

    void Dump() const
    {
        // Show reason first
        if (m_reason != NULL) {
            m_reason->Dump();
        }

        // Afterward, dump exception
        const char *file = strchr(m_path.c_str(), '/');

        if (file == NULL) {
            file = m_path.c_str();
        } else {
            ++file;
        }

        printf("\033[0;36m[%s:%i]\033[m %s() \033[4;35m%s\033[m: %s\033[m\n",
               file, m_line,
               m_function.c_str(),
               m_className.c_str(),
               m_message.empty() ? "<EMPTY>" : m_message.c_str());
    }

    std::string DumpToString() const
    {
        std::string ret;
        if (m_reason != NULL) {
            ret = m_reason->DumpToString();
        }

        const char *file = strchr(m_path.c_str(), '/');

        if (file == NULL) {
            file = m_path.c_str();
        } else {
            ++file;
        }

        char buf[1024];
        snprintf(buf,
                 sizeof(buf),
                 "\033[0;36m[%s:%i]\033[m %s() \033[4;35m%s\033[m: %s\033[m\n",
                 file,
                 m_line,
                 m_function.c_str(),
                 m_className.c_str(),
                 m_message.empty() ? "<EMPTY>" : m_message.c_str());

        buf[sizeof(buf) - 1] = '\n';
        ret += buf;

        return ret;
    }

    Exception *GetReason() const
    {
        return m_reason;
    }

    std::string GetPath() const
    {
        return m_path;
    }

    std::string GetFunction() const
    {
        return m_function;
    }

    int GetLine() const
    {
        return m_line;
    }

    std::string GetMessage() const
    {
        return m_message;
    }

    std::string GetClassName() const
    {
        return m_className;
    }
};
} // namespace CKM

#define Try try

#define Throw(ClassName) \
    throw ClassName(__FILE__, __FUNCTION__, __LINE__)

#define ThrowMsg(ClassName, Message)                                                 \
    do                                                                               \
    {                                                                                \
        std::ostringstream dplLoggingStream;                                         \
        dplLoggingStream << Message;                                                 \
        throw ClassName(__FILE__, __FUNCTION__, __LINE__, dplLoggingStream.str());   \
    } while (0)

#define ReThrow(ClassName) \
    throw ClassName(__FILE__, __FUNCTION__, __LINE__, _rethrown_exception)

#define ReThrowMsg(ClassName, Message) \
    throw ClassName(__FILE__, \
                    __FUNCTION__, \
                    __LINE__, \
                    _rethrown_exception, \
                    Message)

#define Catch(ClassName) \
    catch (const ClassName &_rethrown_exception)

#define DECLARE_EXCEPTION_TYPE(BaseClass, Class)                                                                                          \
    class Class :                                                                                                                                 \
        public BaseClass                                                                                                                \
    {                                                                                                                                     \
      public:                                                                                                                               \
        Class(const char *path, \
              const char *function, \
              int line, \
              const std::string & message = std::string()) :                                                                                                                             \
            BaseClass(path, function, line, message)                                                                                    \
        {                                                                                                                                 \
            BaseClass::m_className = #Class;                                                                                              \
        }                                                                                                                                 \
                                                                                                                                          \
        Class(const char *path, \
              const char *function, \
              int line, \
              const CKM::Exception & reason, \
              const std::string & message = std::string()) :                                                                                                                             \
            BaseClass(path, function, line, reason, message)                                                                            \
        {                                                                                                                                 \
            BaseClass::m_className = #Class;                                                                                              \
        }                                                                                                                                 \
    };

#define UNHANDLED_EXCEPTION_HANDLER_BEGIN try

#define UNHANDLED_EXCEPTION_HANDLER_END                                                                   \
    catch (const CKM::Exception &exception)                                                               \
    {                                                                                                     \
        std::ostringstream msg;                                                                           \
        msg << CKM::Exception::KnownExceptionToString(exception);                                         \
        CKM::LogUnhandledException(msg.str(), __FILE__, __LINE__, __FUNCTION__);                          \
        abort();                                                                                          \
    }                                                                                                     \
    catch (std::exception& e)                                                                             \
    {                                                                                                     \
        std::ostringstream msg;                                                                           \
        msg << e.what();                                                                                  \
        msg << "\n";                                                                                      \
        msg << CKM::Exception::UnknownExceptionToString();                                                \
        CKM::LogUnhandledException(msg.str(), __FILE__, __LINE__, __FUNCTION__);                          \
        abort();                                                                                          \
    }                                                                                                     \
    catch (...)                                                                                           \
    {                                                                                                     \
        std::ostringstream msg;                                                                           \
        msg << CKM::Exception::UnknownExceptionToString();                                                \
        CKM::LogUnhandledException(msg.str(), __FILE__, __LINE__, __FUNCTION__);                          \
        abort();                                                                                          \
    }

namespace CKM {
namespace CommonException {
/**
 * Internal exception definitions
 *
 * These should normally not happen.
 * Usually, exception trace with internal error includes
 * important messages.
 */
DECLARE_EXCEPTION_TYPE(Exception, InternalError) ///< Unexpected error from
                                                 // underlying libraries or
                                                 // kernel
}
}

#endif // CENT_KEY_EXCEPTION_H
