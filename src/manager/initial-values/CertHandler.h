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
 * @file        CertHandler.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       CertHandler class.
 */

#ifndef CERTHANDLER_H_
#define CERTHANDLER_H_

#include <parser.h>
#include <InitialValueHandler.h>

namespace CKM {
namespace InitialValues {

class CertHandler : public InitialValueHandler
{
public:
    explicit CertHandler(CKMLogic & db_logic) : InitialValueHandler(db_logic) {}
    virtual ~CertHandler();

    virtual DataType getDataType() const;
};

}
}
#endif /* CERTHANDLER_H_ */
