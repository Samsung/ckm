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
 *
 *
 * @file        parser.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       XML parser class implementation.
 */

#include <string>
#include <sstream>
#include <algorithm>
#include <xml-utils.h>

namespace
{
const char * const WHITESPACE       = " \n\r\t\v";
const char * const LINE_WHITESPACE  = " \t";

std::string trim_left(const std::string& s, const char *whitespaces)
{
    size_t startpos = s.find_first_not_of(whitespaces);
    return (startpos == std::string::npos) ? "" : s.substr(startpos);
}

std::string trim_right(const std::string& s, const char *whitespaces)
{
    size_t endpos = s.find_last_not_of(whitespaces);
    return (endpos == std::string::npos) ? "" : s.substr(0, endpos+1);
}

std::string trim(const std::string& s, const char *whitespaces)
{
    return trim_right(trim_left(s, whitespaces), whitespaces);
}
}

namespace CKM {
namespace XML {
std::string trim(const std::string& s)
{
    return ::trim(s, WHITESPACE);
}

std::string trimEachLine(const std::string& s)
{
    std::istringstream stream(s);
    size_t line_cnt = 0;
    std::string line, output;
    while(std::getline(stream, line)) {
        if(line_cnt>0)
            output += "\n";
        output += ::trim(line, LINE_WHITESPACE);
        line_cnt ++;
    }
    return output;
}
}
}
