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
 * @file        db-row.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       OBJECT_TABLE entry enhanced with corresponding NAME_TABLE identifier
 */
#pragma once

#include <vector>
#include <ckm/ckm-type.h>
#include <protocols.h>
#include <token.h>

namespace CKM {
namespace DB {

struct Row : public Token {
    Row() = default;

    Row(Token token,
        const Name &pName,
        const Label &pLabel,
        int pExportable) :
        Token(std::move(token))
      , name(pName)
      , ownerLabel(pLabel)
      , exportable(pExportable)
      , algorithmType(DBCMAlgType::NONE)
      , encryptionScheme(0)
      , dataSize(data.size())
    {
    }

    Name name;
    Label ownerLabel;
    int exportable;
    DBCMAlgType algorithmType;  // Algorithm type used for row data encryption
    int encryptionScheme;       // for example: (ENCR_BASE64 | ENCR_PASSWORD)
    RawBuffer iv;               // encoded in base64
    int dataSize;               // size of information without hash and padding
    RawBuffer tag;              // tag for Aes Gcm algorithm
};

typedef std::vector<Row> RowVector;

} // namespace DB
} // namespace CKM

