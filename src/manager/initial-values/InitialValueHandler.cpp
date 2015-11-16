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
 * @file        InitialValueHandler.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       InitialValueHandler class implementation.
 */

#include <sstream>
#include <algorithm>
#include <memory>
#include <exception>
#include <InitialValueHandler.h>
#include <EncodingType.h>
#include <ckm/ckm-type.h>

namespace
{
const char * const XML_ATTR_NAME        = "name";
const char * const XML_ATTR_PASSWORD    = "password";
const char * const XML_ATTR_EXPORTABLE  = "exportable";
}

namespace CKM {
namespace InitialValues {

void InitialValueHandler::Start(const XML::Parser::Attributes &attr)
{
    // get name
    if(attr.find(XML_ATTR_NAME) != attr.end())
        m_name = Alias(attr.at(XML_ATTR_NAME));

    // get password
    if(attr.find(XML_ATTR_PASSWORD) != attr.end())
        m_password = Password(attr.at(XML_ATTR_PASSWORD).c_str());

    // get exportable
    if(attr.find(XML_ATTR_EXPORTABLE) != attr.end())
    {
        std::string flagVal = attr.at(XML_ATTR_EXPORTABLE);
        std::transform(flagVal.begin(), flagVal.end(), flagVal.begin(), ::tolower);
        std::istringstream is(flagVal);
        is >> std::boolalpha >> m_exportable;
    }
}

void InitialValueHandler::End()
{
    if(m_bufferHandler)
    {
        // save data
        Policy policy(m_password, m_exportable);
        int ec = m_db_logic.verifyAndSaveDataHelper(
                Credentials(CKMLogic::SYSTEM_DB_UID, OWNER_ID_SYSTEM),
                m_name,
                OWNER_ID_SYSTEM,
                m_bufferHandler->getData(),
                getDataType(),
                PolicySerializable(policy));
        if(CKM_API_SUCCESS == ec)
        {
            // save permissions
            for(const auto & permission : m_permissions)
            {
                ec = m_db_logic.setPermissionHelper(
                        Credentials(CKMLogic::SYSTEM_DB_UID, OWNER_ID_SYSTEM),
                        m_name,
                        OWNER_ID_SYSTEM,
                        permission->getAccessor(),
                        Permission::READ);
                if(CKM_API_SUCCESS != ec)
                    LogError("Saving permission to: " << m_name << " with params: accessor("<<permission->getAccessor()<<") failed, code: " << ec);
            }
        }
        else
            LogError("Saving type: " << getDataType() << " with params: name("<<m_name<<"), exportable("<<m_exportable<<") failed, code: " << ec);
    }
    else
        LogError("Invalid data with name: " << m_name << ", reason: no key data!");
}

BufferHandler::BufferHandlerPtr InitialValueHandler::CreateBufferHandler(EncodingType type)
{
    m_bufferHandler = std::make_shared<BufferHandler>(type);
    return m_bufferHandler;
}

PermissionHandler::PermissionHandlerPtr InitialValueHandler::CreatePermissionHandler()
{
    PermissionHandler::PermissionHandlerPtr newPermission = std::make_shared<PermissionHandler>();
    m_permissions.push_back(newPermission);
    return newPermission;
}

}
}
