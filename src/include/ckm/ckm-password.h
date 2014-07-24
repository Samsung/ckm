/* Copyright (c) 2014 Samsung Electronics Co.
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
 * @file        safe-buffer.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Custom allocator for std
 */

#ifndef _SAFE_PASSWORD_H_
#define _SAFE_PASSWORD_H_

#include <ckm/ckm-raw-buffer.h>
#include <boost/container/string.hpp>

namespace CKM {

typedef boost::container::basic_string<char, std::char_traits<char>, erase_on_dealloc<char>> Password;

} // namespace CKM

#endif //_ERASE_ON_DEALLOC_H_
