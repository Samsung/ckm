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
 * @file        xml-utils.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       XML utils.
 */

#ifndef XML_UTILS_H_
#define XML_UTILS_H_

#include <string>
#include <ckm/ckm-raw-buffer.h>
namespace CKM {
namespace XML
{

RawBuffer removeWhiteChars(const RawBuffer &buffer);
std::string trim(const std::string& s);
std::string trimEachLine(const std::string &s);

}
}
#endif /* XML_UTILS_H_ */
