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
 * @file        abstract_log_provider.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of abstract log provider
 */
#ifndef CENT_KEY_ABSTRACT_LOG_PROVIDER_H
#define CENT_KEY_ABSTRACT_LOG_PROVIDER_H

namespace CKM {
namespace Log {
class AbstractLogProvider {
  public:
    enum class LogLevel {
        None,
        Error,
        Warning,
        Info,
        Debug,
        Pedantic
    };

    virtual ~AbstractLogProvider() {}

    virtual void SetTag(const char *tag);

    virtual void Log(LogLevel level,
                     const char *message,
                     const char *fileName,
                     int line,
                     const char *function) const = 0;

  protected:
    static const char *LocateSourceFileName(const char *filename);
};
}
} // namespace CKM

#endif // CENT_KEY_ABSTRACT_LOG_PROVIDER_H
