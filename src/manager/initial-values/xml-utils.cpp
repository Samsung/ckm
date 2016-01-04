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

namespace {
const char * const WHITESPACE       = " \n\r\t\v";
const char * const LINE_WHITESPACE  = " \r\t\v";

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

template <typename T>
T removeChars(const T& input, const char *what)
{
    T out(input);
    auto endit = std::remove_if(out.begin(), out.end(),
        [what](char c)
        {
            for (const char *ptr = what; *ptr; ++ptr)
                if (*ptr == c)
                    return true;
            return false;
        });

    out.erase(endit, out.end());
    return out;
}

RawBuffer removeWhiteChars(const RawBuffer &buffer)
{
    return removeChars(buffer, WHITESPACE);
}

std::string trimEachLine(const std::string& input)
{
    std::stringstream ss(input);
    std::stringstream output;
    std::string line;

    while (std::getline(ss, line, '\n')) {
        auto afterTrim = ::trim(line, LINE_WHITESPACE);
        if (!afterTrim.empty())
            output << afterTrim << std::endl;
    }

    return output.str();
}

std::string trim(const std::string &s)
{
    return removeChars(s, WHITESPACE);
}

} // namespace XML
} // namespace CKM

