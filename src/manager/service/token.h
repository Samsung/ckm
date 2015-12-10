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
 * @file        token.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       OBJECT_TABLE entry enhanced with corresponding NAME_TABLE identifier
 */
#pragma once

#include <utility>

#include <data-type.h>
#include <crypto-backend.h>

namespace CKM {

struct Token {
    Token() :
        backendId(CryptoBackend::None)
    {
    }

    Token(CryptoBackend pBackendId, DataType pDataType, const RawBuffer &pData) :
        backendId(pBackendId),
        dataType(pDataType),
        data(pData)
    {
    }
    CryptoBackend backendId;
    DataType dataType;
    RawBuffer data;
};

typedef std::pair<Token, Token> TokenPair;

} // namespace CKM
