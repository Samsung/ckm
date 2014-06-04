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
 * @brief       Implementation of self wiping out string for sensitive data
 */
#include <dpl/TransitoryString.h>
#include <cstring>
#include <dpl/assert.h>
namespace CKM {
TransitoryString::TransitoryString(char c, std::size_t length){
    m_length = length;
    m_tString = new char[m_length+1];
    memset(m_tString, c, m_length);
    m_tString[m_length] = '\0';
}

TransitoryString::TransitoryString(TransitoryString&& other)
    : m_tString(other.m_tString),
      m_length(other.m_length)
{
    other.m_length = 0;
    other.m_tString = NULL;
}

TransitoryString::~TransitoryString(){
    if(m_tString != NULL) {
        wipeOut();
        delete[] m_tString;
        m_length = 0;
    }
}

TransitoryString& TransitoryString::operator=(TransitoryString&& other) {
    if (this != &other) {
        delete[] m_tString;

        m_tString = other.m_tString;
        m_length = other.m_length;

        other.m_tString = NULL;
        other.m_length = 0;
    }
    return *this;
}

void TransitoryString::wipeOut(){
    for(std::size_t i = 0; i < m_length; i++)
        m_tString[i] = '\0';
    AssertMsg(strlen(m_tString) == 0, "Wiping out string didn't work!");
    for(std::size_t i = 0; i < m_length; i++)
        AssertMsg(m_tString[i] == '\0', "Wiping out string didn't work!");
}
} // CKM
