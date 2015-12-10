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
 * @file        naive_synchronization_object.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of SQL naive
 * synchronization object
 */
#include <stddef.h>
#include <dpl/db/naive_synchronization_object.h>
#include <dpl/assert.h>
#include <time.h>

namespace {
    unsigned int seed = time(NULL);
}

//Taken from Thread class, so we don't have to pull whole definition
//(only this part is needed)
namespace Thread {

static const size_t NANOSECONDS_PER_SECOND =
    static_cast<uint64_t>(1000 * 1000 * 1000);

static const size_t NANOSECONDS_PER_MILISECOND =
    static_cast<uint64_t>(1000 * 1000);

void NanoSleep(uint64_t nanoseconds)
{
    timespec requestedTime = {
        static_cast<time_t>(
            nanoseconds / NANOSECONDS_PER_SECOND),

        static_cast<long>(
            nanoseconds % NANOSECONDS_PER_SECOND)
    };

    timespec remainingTime;

    for (;;) {
        if (nanosleep(&requestedTime, &remainingTime) == 0)
            break;

        int error = errno;
        Assert(error == EINTR);

        requestedTime = remainingTime;
    }
}

void MiliSleep(uint64_t miliseconds)
{
    NanoSleep(miliseconds * NANOSECONDS_PER_MILISECOND);
}
}

namespace CKM {
namespace DB {
void NaiveSynchronizationObject::Synchronize()
{
    // Sleep for about 10ms - 30ms
    Thread::MiliSleep(10 + rand_r(&seed) % 20);
}

void NaiveSynchronizationObject::NotifyAll()
{
    // No need to inform about anything
}
} // namespace DB
} // namespace CKM
