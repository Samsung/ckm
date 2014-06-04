/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        TransitoryString.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Header of self wiping out string for sensitive data
 */
#ifndef TRANSITORY_STRING_H
#define TRANSITORY_STRING_H

#include <cstring>

namespace CKM {
class TransitoryString {
    public:
        static const std::size_t PREFERRED_SIZE = 64;

        static std::size_t getPreferredSize() {
            return PREFERRED_SIZE;
        }

        TransitoryString() = delete;
        TransitoryString(const TransitoryString&) = delete;
        TransitoryString(TransitoryString&) = delete;
        TransitoryString(TransitoryString&& tString);
        TransitoryString(char c, std::size_t length);
        ~TransitoryString();

        TransitoryString& operator=(const TransitoryString& other) = delete;
        TransitoryString& operator=(TransitoryString&& other);

        char& operator[](std::size_t index) {
            return m_tString[index];
        }

        const char* c_str() const {
            return m_tString;
        }

        const char* data() const {
            return m_tString;
        }

        std::size_t length() const {
            return m_length;
        }
    private:
        char* m_tString;
        std::size_t m_length;

        void wipeOut();

};
} // CKM
#endif // TRANSITORY_STRING_H
