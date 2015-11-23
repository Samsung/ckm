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
 *
 *
 * @file        initial-value-loader.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#include <dirent.h>

#include <initial-value-loader.h>

#include <ckm-logic.h>
#include <InitialValuesFile.h>

namespace {
const char * const INIT_VALUES_DIR          = "/opt/data/ckm/initial_values/";
const char * const INIT_VALUES_XSD          = "/usr/share/ckm/initial_values.xsd";
const char * const INIT_VALUES_FILE_SUFFIX  = ".xml";
} // namespace anonymous

namespace CKM {
namespace InitialValues {

void LoadFiles(CKMLogic &logic) {
    try {
        std::vector<std::string> filesToParse;
        DIR *dp = opendir(INIT_VALUES_DIR);
        if(dp)
        {
            struct dirent *entry;
            while ((entry = readdir(dp)))
            {
                std::string filename = std::string(entry->d_name);

                // check if XML file
                std::string lowercaseFilename = filename;
                std::transform(lowercaseFilename.begin(), lowercaseFilename.end(), lowercaseFilename.begin(), ::tolower);
                if(lowercaseFilename.find(INIT_VALUES_FILE_SUFFIX) == std::string::npos)
                    continue;

                filesToParse.push_back(std::string(INIT_VALUES_DIR) + filename);
            }
            closedir(dp);
        }

        // parse
        for(const auto & file : filesToParse)
        {
            InitialValues::InitialValuesFile xmlFile(file.c_str(), logic);
            int rc = xmlFile.Validate(INIT_VALUES_XSD);
            if(rc == XML::Parser::PARSE_SUCCESS)
            {
                rc = xmlFile.Parse();
                if(rc != XML::Parser::PARSE_SUCCESS)
                    LogError("invalid initial values file: " << file << ", parsing code: " << rc);
            }
            else
                LogError("invalid initial values file: " << file << ", validation code: " << rc);
            unlink(file.c_str());
        }
    } catch (...) {
        LogError("The implementation of exception handling in xml parser is broken!");
    }
}

} // namespace InitialValues
} // namespace CKM

