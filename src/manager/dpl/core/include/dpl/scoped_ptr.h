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
 * @file        scoped_free.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation of scoped free pointer
 */

#ifndef SCOPED_PTR_H
#define SCOPED_PTR_H

#include <memory>

namespace CKM {
struct free_deleter{
    void operator()(char *p)
    {
        free(p);
    }
};

typedef std::unique_ptr<char, free_deleter> CharUniquePtr;
}
#endif // SCOPED_PTR_H
