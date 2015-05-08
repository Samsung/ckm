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
 * @file        BufferHandler.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       BufferHandler class implementation.
 */

#include <string>
#include <algorithm>
#include <cctype>
#include <BufferHandler.h>
#include <xml-utils.h>
#include <base64.h>

namespace CKM {
namespace InitialValues {

BufferHandler::BufferHandler(EncodingType type) : m_encoding(type) {}
BufferHandler::~BufferHandler() {}

void BufferHandler::Start(const XML::Parser::Attributes &)
{
}


void BufferHandler::Characters(const std::string & data)
{
    m_data.reserve(m_data.size() + data.size());
    m_data.insert(m_data.end(), data.begin(), data.end());
}

void BufferHandler::End()
{
    switch(m_encoding)
    {
        // PEM requires that "----- END" section comes right after "\n" character
        case PEM:
        {
            std::string trimmed = XML::trimEachLine(std::string(m_data.begin(), m_data.end()));
            m_data = RawBuffer(trimmed.begin(), trimmed.end());
            break;
        }

        // Base64 decoder also does not accept any whitespaces
        case DER:
        case BASE64:
        {
            std::string trimmed = XML::trimEachLine(std::string(m_data.begin(), m_data.end()));
            Base64Decoder base64;
            base64.reset();
            base64.append(RawBuffer(trimmed.begin(), trimmed.end()));
            base64.finalize();
            m_data = base64.get();
            break;
        }

        default:
            break;
    }
}

}
}
