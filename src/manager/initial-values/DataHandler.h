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
 * @file        DataHandler.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       DataHandler class.
 */

#ifndef DATAHANDLER_H_
#define DATAHANDLER_H_

#include <parser.h>
#include <InitialValueHandler.h>

namespace CKM {
namespace InitialValues {

class DataHandler : public InitialValueHandler
{
public:
    explicit DataHandler(CKMLogic & db_logic) : InitialValueHandler(db_logic) {}
    virtual ~DataHandler();

    virtual DataType getDataType() const;
};

}
}
#endif /* DATAHANDLER_H_ */
