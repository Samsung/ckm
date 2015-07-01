/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file       exception.h
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once

#include <exception>
#include <string>
#include <iostream>
#include <sstream>

#include <ckm/ckm-error.h>

#include <symbol-visibility.h>
#include <stringify.h>

namespace CKM {
namespace Exc {

class COMMON_API Exception : public std::exception {
public:
    Exception(const char *path, const char *function, int line, const std::string &message = std::string())
      : m_path(path)
      , m_function(function)
      , m_line(line)
      , m_message(message)
    {}

    virtual ~Exception() noexcept {}

    virtual const char *what(void) const noexcept {
        return m_message.c_str();
    }

    virtual std::string message(void) const {
        std::ostringstream msg;
        msg << "[" << m_path << ":" << m_line << " " << m_function << "()] " << m_message;
        return msg.str();
    }

    virtual int error(void) const = 0;

protected:
    std::string m_path;
    std::string m_function;
    int m_line;
    std::string m_message;
};

class DefaultExceptionLogger {
public:
    template <typename... Args>
    DefaultExceptionLogger(const Args&...) {}
};

template<
    int Error = 0,
    typename Stringify = StringifyAvoid,
    typename Before = DefaultExceptionLogger,
    typename After = DefaultExceptionLogger>
class COMMON_API DefineException : public Exception {
public:
    template<typename... Args>
    DefineException(const char *path, const char *function, int line, const Args&... args)
      : Exception(path, function, line, Stringify()(args...))
    {
        Before(m_path, m_function, m_line, DefineException<Error,Stringify,Before,After>::error(), m_message);
    }
    ~DefineException() noexcept {
        After(m_path, m_function, m_line, DefineException<Error,Stringify,Before,After>::error(), m_message);
    }
    virtual int error(void) const {
        return Error;
    }
};

class COMMON_API PrintError {
public:
    PrintError(
        const std::string &path,
        const std::string &function,
        int line, int error,
        const std::string &message = std::string());
};

class COMMON_API PrintDebug {
public:
    PrintDebug(
        const std::string &path,
        const std::string &function,
        int line, int error,
        const std::string &message = std::string());
};

typedef DefineException<CKM_API_ERROR_SERVER_ERROR,
        Stringify, PrintError> InternalError;
typedef DefineException<CKM_API_ERROR_INPUT_PARAM,
        StringifyDebug, PrintDebug> InputParam;
typedef DefineException<CKM_API_ERROR_DB_LOCKED,
        Stringify, PrintError> DatabaseLocked;
typedef DefineException<CKM_API_ERROR_FILE_SYSTEM,
        Stringify, PrintError> FileSystemFailed;
typedef DefineException<CKM_API_ERROR_AUTHENTICATION_FAILED,
        StringifyDebug, PrintDebug> AuthenticationFailed;

} // namespace Exc
} // namespace CKM

#define ThrowErr(name, ...) \
  throw name(__FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);

