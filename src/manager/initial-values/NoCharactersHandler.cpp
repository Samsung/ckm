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
 * @file       NoCharactersHandler.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <NoCharactersHandler.h>

#include <cctype>
#include <algorithm>
#include <exception>

namespace CKM {
namespace InitialValues {

void NoCharactersHandler::Characters(const std::string & data)
{
    auto f = find_if(data.begin(), data.end(), [](char c){ return std::isspace(c) == 0;});
    if(f != data.end())
        throw std::runtime_error(
                "error: value handler detected raw data outside data-specific tag");
}

NoCharactersHandler::~NoCharactersHandler()
{
}

} // namespace InitialValues
} // namespace CKM
