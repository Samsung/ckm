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
 * @file        old_style_log_provider.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of old style log provider
 */
#ifndef CENT_KEY_OLD_STYLE_LOG_PROVIDER_H
#define CENT_KEY_OLD_STYLE_LOG_PROVIDER_H

#include <dpl/log/abstract_log_provider.h>
#include <string>

namespace CKM {
namespace Log {
class OldStyleLogProvider :
    public AbstractLogProvider
{
  private:
    bool m_showDebug;
    bool m_showInfo;
    bool m_showWarning;
    bool m_showError;
    bool m_showPedantic;
    bool m_printStdErr;

    static std::string FormatMessage(const char *message,
                                     const char *filename,
                                     int line,
                                     const char *function);

  public:
    OldStyleLogProvider(bool showDebug,
                        bool showInfo,
                        bool showWarning,
                        bool showError,
                        bool showPedantic);
    OldStyleLogProvider(bool showDebug,
                        bool showInfo,
                        bool showWarning,
                        bool showError,
                        bool showPedantic,
                        bool printStdErr);
    virtual ~OldStyleLogProvider() {}

    virtual void Debug(const char *message,
                       const char *fileName,
                       int line,
                       const char *function);
    virtual void Info(const char *message,
                      const char *fileName,
                      int line,
                      const char *function);
    virtual void Warning(const char *message,
                         const char *fileName,
                         int line,
                         const char *function);
    virtual void Error(const char *message,
                       const char *fileName,
                       int line,
                       const char *function);
    virtual void Pedantic(const char *message,
                          const char *fileName,
                          int line,
                          const char *function);
    virtual void SecureDebug(const char *message,
                       const char *fileName,
                       int line,
                       const char *function);
    virtual void SecureInfo(const char *message,
                      const char *fileName,
                      int line,
                      const char *function);
    virtual void SecureWarning(const char *message,
                         const char *fileName,
                         int line,
                         const char *function);
    virtual void SecureError(const char *message,
                       const char *fileName,
                       int line,
                       const char *function);
};
}
} // namespace CKM

#endif // CENT_KEY_OLD_STYLE_LOG_PROVIDER_H
