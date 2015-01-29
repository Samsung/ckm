/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       log-setup.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <log-setup.h>
#include <fstream>
#include <dpl/log/log.h>
#include <stdexcept>

namespace CKM {

namespace {

const std::string PROVIDER_MATCH("CKM_LOG_PROVIDER=");
const std::string LEVEL_MATCH("CKM_LOG_LEVEL=");

// see the explanation in SetupClientLogSystem() function
bool logSystemReady = false;

/*
 * Reads central-key-manager service environment file. This configuration may be later applied to
 * client so that it uses the same logging method.
 */
class EnvFileParser
{
public:
    EnvFileParser();
    virtual ~EnvFileParser() {}

    std::string getProvider() const { return m_provider; }
    std::string getLevel() const { return m_level; }

private:
    std::string m_provider;
    std::string m_level;
};

EnvFileParser::EnvFileParser()
{
#ifdef SYSTEMD_ENV_FILE
    std::ifstream is(SYSTEMD_ENV_FILE);
    LogDebug("Reading env file: " SYSTEMD_ENV_FILE);

    while(is.good()) {
        std::string line;

        std::getline(is, line);

        if (0 == line.compare(0, PROVIDER_MATCH.size(), PROVIDER_MATCH)) {
            m_provider = line.substr(PROVIDER_MATCH.size());
            LogDebug("Log provider: " << m_provider);
        }
        else if (0 == line.compare(0, LEVEL_MATCH.size(), LEVEL_MATCH)) {
            m_level = line.substr(LEVEL_MATCH.size());
            LogDebug("Log level: " << m_level);
        }
    }
#else
    LogWarning("Log configuration file is undefined");
#endif
}

} // namespace anonymous

void SetupClientLogSystem()
{
    /*
     * This function is called from library constructors. This will prevent from executing the code
     * more than once from single binary (because both client libraries use their constructors to
     * initialize log system). To make it work the code has to be in a common library linked by both
     * clients.
     */
    if (logSystemReady)
        return;

    CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CKM_CLIENT");

    CKM::EnvFileParser parser;
    const std::string provider = parser.getProvider();
    if (!provider.empty()) {
        try {
            CKM::Singleton<CKM::Log::LogSystem>::Instance().SelectProvider(provider);
            // reset tag after changing log provider
            CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CKM_CLIENT");
        } catch(const std::out_of_range&) {
            LogError("Unsupported log provider: " << provider);
        }
    }
    const std::string level = parser.getLevel();
    if (!level.empty())
        CKM::Singleton<CKM::Log::LogSystem>::Instance().SetLogLevel(level.c_str());

    logSystemReady = true;
}

} /* namespace CKM */
