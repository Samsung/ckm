/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       decider.h
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once

#include <memory>

#include <ckm/ckm-type.h>

#include <crypto-backend.h>

#include <generic-backend/gstore.h>
#include <token.h>

namespace CKM {
namespace Crypto {

class Decider {
public:
    Decider();
    GStore& getStore(const Token &token) const;
    GStore& getStore(DataType data, bool exportable) const;

    virtual ~Decider(){}
protected:
    GStore& getStore(CryptoBackend id) const;

    std::unique_ptr<GStore> m_swStore;
    std::unique_ptr<GStore> m_tzStore;
};

} // Crypto
} // CKM

