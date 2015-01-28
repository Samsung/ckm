/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       journal_log_provider.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <dpl/log/journal_log_provider.h>
#include <systemd/sd-journal.h>
#include <map>
#include <stdexcept>

namespace CKM {
namespace Log {

namespace {
std::map<AbstractLogProvider::LogLevel, int> journalLevel = {
        { AbstractLogProvider::LogLevel::Error,     LOG_ERR },
        { AbstractLogProvider::LogLevel::Warning,   LOG_WARNING },
        { AbstractLogProvider::LogLevel::Info,      LOG_INFO },
        { AbstractLogProvider::LogLevel::Debug,     LOG_DEBUG},
        { AbstractLogProvider::LogLevel::Pedantic,  LOG_DEBUG}
};

} // namespace anonymous

JournalLogProvider::JournalLogProvider()
{}

JournalLogProvider::~JournalLogProvider()
{}

void JournalLogProvider::Log(AbstractLogProvider::LogLevel level,
                             const char *message,
                             const char *fileName,
                             int line,
                             const char *function) const
{
    try {
        sd_journal_send("PRIORITY=%d", journalLevel.at(level),
                "CODE_FILE=%s", fileName,
                "CODE_FUNC=%s", function,
                "CODE_LINE=%d", line,
                // add file, line & function info to log message
                "MESSAGE=[%s:%d] %s(): %s", fileName, line, function, message,
                NULL);
    } catch (const std::out_of_range&) {
        sd_journal_send(
                "PRIORITY=%d", LOG_ERR,
                "CODE_FILE=%s", fileName,
                "CODE_FUNC=%s", function,
                "CODE_LINE=%d", line,
                // add file, line & function info to log message
                "MESSAGE=[%s:%d] %s(): Unsupported log level %d", fileName, line, function, level,
                NULL);
    }
}

} /* namespace Log */
} /* namespace CKM */
