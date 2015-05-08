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
 * @file        KeyHandler.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       KeyHandler class implementation.
 */

#include <string>
#include <algorithm>
#include <parser.h>
#include <KeyHandler.h>
#include <InitialValueHandler.h>
#include <ckm/ckm-type.h>

namespace
{
const char * const XML_ATTR_TYPE    = "type";
const char * const XML_ATTR_TYPE_VAL_RSA_PRV    =   "RSA_PRV";
const char * const XML_ATTR_TYPE_VAL_RSA_PUB    =   "RSA_PUB";
const char * const XML_ATTR_TYPE_VAL_DSA_PRV    =   "DSA_PRV";
const char * const XML_ATTR_TYPE_VAL_DSA_PUB    =   "DSA_PUB";
const char * const XML_ATTR_TYPE_VAL_ECDSA_PRV  =   "ECDSA_PRV";
const char * const XML_ATTR_TYPE_VAL_ECDSA_PUB  =   "ECDSA_PUB";
const char * const XML_ATTR_TYPE_VAL_AES        =   "AES";
}

namespace CKM {
namespace InitialValues {

KeyHandler::~KeyHandler() {}

void KeyHandler::Start(const XML::Parser::Attributes &attr)
{
    InitialValueHandler::Start(attr);

    // get key type
    if(attr.find(XML_ATTR_TYPE) != attr.end())
        m_keyType = KeyHandler::parseType(attr.at(XML_ATTR_TYPE));
}

KeyType KeyHandler::parseType(const std::string & typeStr)
{
    if     (typeStr == XML_ATTR_TYPE_VAL_RSA_PRV)      return KeyType::KEY_RSA_PRIVATE;
    else if(typeStr == XML_ATTR_TYPE_VAL_RSA_PUB)      return KeyType::KEY_RSA_PUBLIC;
    else if(typeStr == XML_ATTR_TYPE_VAL_DSA_PRV)      return KeyType::KEY_DSA_PRIVATE;
    else if(typeStr == XML_ATTR_TYPE_VAL_DSA_PUB)      return KeyType::KEY_DSA_PUBLIC;
    else if(typeStr == XML_ATTR_TYPE_VAL_ECDSA_PRV)    return KeyType::KEY_ECDSA_PRIVATE;
    else if(typeStr == XML_ATTR_TYPE_VAL_ECDSA_PUB)    return KeyType::KEY_ECDSA_PUBLIC;
    else if(typeStr == XML_ATTR_TYPE_VAL_AES)          return KeyType::KEY_AES;
    else // should not happen
        throw std::runtime_error("error: invalid value discovered as key type");
}

DataType KeyHandler::getDataType() const
{
    return DataType(m_keyType);
}

}
}
