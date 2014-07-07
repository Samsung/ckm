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
 * @author      Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version     1.0
 * @brief       Custom allocator for std
 */

#ifndef _SAFE_BUFFER_H_
#define _SAFE_BUFFER_H_

#include <string.h>

#include <boost/container/vector.hpp>

namespace CKM {

template <typename T>
struct erase_on_dealloc {
    typedef T value_type;

    erase_on_dealloc() noexcept {}

    template <typename U>
    erase_on_dealloc (const erase_on_dealloc<U>&) noexcept {}

    T* allocate (std::size_t n)
    {
        return static_cast<T*>(::operator new(n*sizeof(T)));
    }

    void deallocate (T* p, std::size_t n)
    {
        // clear the memory before deleting
        memset(p,0,n*sizeof(T));
        ::operator delete(p);
    }
};

template <typename T, typename U>
constexpr bool operator== (const erase_on_dealloc<T>&, const erase_on_dealloc<U>&) noexcept
{
    return true;
}

template <typename T, typename U>
constexpr bool operator!= (const erase_on_dealloc<T>&, const erase_on_dealloc<U>&) noexcept
{
    return false;
}

/*
 * TODO replace with:
 *
 *  template <typename T>
 *  using SafeBuffer = std::vector<T, erase_on_dealloc<T>>;
 *
 *  typedef SafeBuffer<unsigned char> RawBuffer
 *
 * when gcc 4.7/4.8 is available. Also replace boost::vector with std::vector
 * in other parts of code
 */
template <typename T>
struct SafeBufferT {
    typedef boost::container::vector<T, erase_on_dealloc<T>> Type;
};

// used to pass password and raw key data
typedef SafeBufferT<unsigned char>::Type SafeBuffer;

} // namespace CKM

#endif //_ERASE_ON_DEALLOC_H_
