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
 * @file        InitialValueHandler.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       InitialValueHandler class.
 */

#ifndef INITIALVALUEHANDLER_H_
#define INITIALVALUEHANDLER_H_

#include <parser.h>
#include <BufferHandler.h>
#include <PermissionHandler.h>
#include <NoCharactersHandler.h>
#include <EncodingType.h>
#include <ckm/ckm-type.h>
#include <ckm-logic.h>
#include <protocols.h>

namespace CKM {
namespace InitialValues {

class InitialValueHandler : public NoCharactersHandler
{
public:
    typedef std::shared_ptr<InitialValueHandler> InitialValueHandlerPtr;

    explicit InitialValueHandler(CKMLogic & db_logic) : m_exportable(false),
                                                        m_db_logic(db_logic) {}
    virtual ~InitialValueHandler() {};

    BufferHandler::BufferHandlerPtr CreateBufferHandler(EncodingType type);
    PermissionHandler::PermissionHandlerPtr CreatePermissionHandler();
    virtual void Start(const XML::Parser::Attributes &);
    virtual void End();

protected:
    virtual DataType getDataType() const = 0;

    Alias      m_name;
    Password   m_password;
    bool       m_exportable;
    CKMLogic & m_db_logic;

    BufferHandler::BufferHandlerPtr m_bufferHandler;
    std::vector<PermissionHandler::PermissionHandlerPtr> m_permissions;
};

}
}
#endif /* INITIALVALUEHANDLER_H_ */
