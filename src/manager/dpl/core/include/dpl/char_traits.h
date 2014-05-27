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
 * @file        char_traits.h
 * @author      Piotr Marcinkiewicz (p.marcinkiew@samsung.com)
 * @version     1.0
 * @brief       Char traits are used to create basic_string extended with
 * additional features
 *              Current char traits could be extended in feature to boost
 * performance
 */
#ifndef CKM_CHAR_TRAITS
#define CKM_CHAR_TRAITS

#include <cstring>
#include <string>
#include <ostream>
#include <algorithm>
#include <dpl/exception.h>

namespace CKM {
typedef std::char_traits<wchar_t> CharTraits;
} // namespace CKM

#endif // CKM_CHAR_TRAITS
