/*
 *  Copyright (c) 2014 Samsung Electronics Co.
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
 * @file        ocsp-logic.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       OCSP logic implementation.
 */
#pragma once

#include <ckm/ckm-type.h>

namespace CKM {

class OCSPLogic {
public:
    OCSPLogic(){}
    OCSPLogic(const OCSPLogic &) = delete;
    OCSPLogic(OCSPLogic &&) = delete;
    OCSPLogic& operator=(const OCSPLogic &) = delete;
    OCSPLogic& operator=(OCSPLogic &&) = delete;

    RawBuffer ocspCheck(int commandId, const RawBufferVector &rawChain);
    virtual ~OCSPLogic(){}
};



} // namespace CKM

