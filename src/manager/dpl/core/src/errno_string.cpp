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
 * @file        errno_string.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of errno string
 */
#include <stddef.h>
#include <dpl/errno_string.h>
#include <dpl/assert.h>
#include <dpl/exception.h>
#include <dpl/assert.h>
#include <dpl/scoped_ptr.h>
#include <string>
#include <cstddef>
#include <cstring>
#include <malloc.h>
#include <cerrno>
#include <stdexcept>
#include <memory>

namespace CKM {
namespace // anonymous
{
const size_t DEFAULT_ERRNO_STRING_SIZE = 32;
} // namespace anonymous

std::string GetErrnoString(int error)
{
    size_t size = DEFAULT_ERRNO_STRING_SIZE;
    char *buffer = NULL;

    for (;;) {
        // Add one extra characted for end of string null value
        char *newBuffer = static_cast<char *>(::realloc(buffer, size + 1));

        if (!newBuffer) {
            // Failed to realloc
            ::free(buffer);
            throw std::bad_alloc();
        }

        // Setup reallocated buffer
        buffer = newBuffer;
        ::memset(buffer, 0, size + 1);

        // Try to retrieve error string
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
        // The XSI-compliant version of strerror_r() is provided if:
        int result = ::strerror_r(error, buffer, size);

        if (result == 0) {
            CharUniquePtr scopedBufferFree(buffer);
            return std::string(buffer);
        }
#else
        errno = 0;

        // Otherwise, the GNU-specific version is provided.
        char *result = ::strerror_r(error, buffer, size);

        if (result != NULL) {
            CharUniquePtr scopedBufferFree(buffer);
            return std::string(result);
        }
#endif

        // Interpret errors
        switch (errno) {
        case EINVAL:
            // We got an invalid errno value
                ::free(buffer);
            ThrowMsg(InvalidErrnoValue, "Invalid errno value: " << error);

        case ERANGE:
            // Incease buffer size and retry
            size <<= 1;
            continue;

        default:
            AssertMsg(0, "Invalid errno value after call to strerror_r!");
        }
    }
}
} // namespace CKM
