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
 * @file       stringify.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once

#include <sstream>
#include <string>

namespace CKM {

template <bool Mode>
class StringifyBasic;

template <>
class StringifyBasic<false> {
    StringifyBasic() = delete;
public:
    static std::string Merge() {
        return std::string();
    }

    template <typename... Args>
    static std::string Merge(const Args&...){
        return std::string();
    }
};

template <>
class StringifyBasic<true> {
    StringifyBasic() = delete;

    static void Concatenate(std::ostringstream&) {}

    template <typename t, typename... Args>
    static void Concatenate(std::ostringstream& stream, const t& arg1, const Args&... args) {
        stream << arg1;
        Concatenate(stream, args...);
    }
public:
    static std::string Merge() {
        return std::string();
    }

    template <typename T, typename... Args>
    static std::string Merge(const T& arg1, const Args&... args) {
        std::ostringstream stream;
        Concatenate(stream, arg1, args...);
        return stream.str();
    }
};

#ifdef DEBUG
#define DEBUG_STATUS true
#else
#define DEBUG_STATUS false
#endif

typedef StringifyBasic<true>  Stringify;
typedef StringifyBasic<false> StringifyAvoid;
typedef StringifyBasic<true>  StringifyError;
typedef StringifyBasic<DEBUG_STATUS> StringifyDebug;

#undef DEBUG_STATUS

} // namespace CKM

