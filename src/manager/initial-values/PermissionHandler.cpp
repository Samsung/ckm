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
 * @file        PermissionHandler.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       PermissionHandler class implementation.
 */

#include <ckm/ckm-type.h>
#include <PermissionHandler.h>

namespace {
const char * const XML_ATTR_ACCESSOR    = "accessor";
}

namespace CKM {
namespace InitialValues {

PermissionHandler::~PermissionHandler() {}

void PermissionHandler::Start(const XML::Parser::Attributes & attr)
{
    // get accessor label
    if (attr.find(XML_ATTR_ACCESSOR) != attr.end())
        m_accessor = Label(attr.at(XML_ATTR_ACCESSOR));
}

void PermissionHandler::End()
{
}

}
}
