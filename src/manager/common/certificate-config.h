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
 * @file       certificate-config.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <set>
#include <string>
#include <symbol-visibility.h>

#pragma once

namespace CKM {

class COMMON_API CertificateConfig
{
public:
    static void addSystemCertificateDir(const std::string& dir) { m_sysCertDirs.insert(dir); }
    static void addSystemCertificateFile(const std::string& file) { m_sysCertFiles.insert(file); }

    typedef std::set<std::string> PathSet;

    static const PathSet& getSystemCertificateDirs() { return m_sysCertDirs; }
    static const PathSet& getSystemCertificateFiles() { return m_sysCertFiles; }

private:
    CertificateConfig();

    static PathSet m_sysCertDirs;
    static PathSet m_sysCertFiles;
};

} /* namespace CKM */
