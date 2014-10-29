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
 * @file       stringify.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <sstream>
#include <string>

namespace CKM {

/*
 * Helper functions for easy argument concatenation. Can be used in logs and exceptions.
 * Ex)
 * template <typename... Args>
 * std::runtime_error my_exception(const Args&... args)
 * {
 *     return std::runtime_error(stringify(args...));
 * };
 *
 * throw my_exception("Function foo has failed. Status: ", status, " error code: ", error);
 */

std::string stringify() {
    return std::string();
}

void concatenate(std::ostringstream&) {}

template <typename T, typename... Args>
void concatenate(std::ostringstream& stream, const T& arg1, const Args&... args) {
    stream << arg1;
    concatenate(stream, args...);
}

template <typename T, typename... Args>
std::string stringify(const T& arg1, const Args&... args){
    std::ostringstream stream;
    concatenate(stream, arg1, args...);
    return stream.str();
}

} // namespace CKM
