/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        naive_synchronization_object.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of SQL naive
 * synchronization object
 */
#ifndef CKM_NAIVE_SYNCHRONIZATION_OBJECT_H
#define CKM_NAIVE_SYNCHRONIZATION_OBJECT_H

#include <dpl/db/sql_connection.h>

namespace CKM {
namespace DB {
/**
 * Naive synchronization object used to synchronize SQL connection
 * to the same database across different threads and processes
 */
class NaiveSynchronizationObject :
    public SqlConnection::SynchronizationObject
{
  public:
    // [SqlConnection::SynchronizationObject]
    virtual void Synchronize();
    virtual void NotifyAll();
};
} // namespace DB
} // namespace CKM

#endif // CKM_NAIVE_SYNCHRONIZATION_OBJECT_H
