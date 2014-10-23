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
 * @file        ckm-raw-buffer.h
 * @author      Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version     1.0
 * @brief       Custom allocator for std
 */

#ifndef _SAFE_BUFFER_H_
#define _SAFE_BUFFER_H_

#include <stddef.h>
#include <string.h>
#include <vector>

namespace CKM {

template <typename T>
struct std_erase_on_dealloc
{
    // MJK: if re-factoring, remember not to inherit from the std::allocator !
    // MJK: to be replaced with much shorter version once std::allocator_traits
    // becomes supported in STL containers (i.e. list, vector and string)
    typedef size_t    size_type;
    typedef ptrdiff_t difference_type;
    typedef T*        pointer;
    typedef const T*  const_pointer;
    typedef T&        reference;
    typedef const T&  const_reference;
    typedef T         value_type;

    std_erase_on_dealloc() = default;

    template <typename U>
    std_erase_on_dealloc(const std_erase_on_dealloc<U>&) {}

    T* allocate(std::size_t n) {
        return static_cast<T*>(::operator new(n*sizeof(T)));
    }

    void deallocate(T* ptr, std::size_t n) {
        // clear the memory before deleting
        memset(ptr, 0 ,n * sizeof(T));
        ::operator delete(ptr);
    }

    template<typename _Tp1>
    struct rebind
    {
        typedef std_erase_on_dealloc<_Tp1> other;
    };

    void construct(pointer p, const T& val) {
        new (p) T(val);
    }

    void destroy(pointer p) {
        p->~T();
    }

    size_type max_size() const {
        return size_type(-1);
    }
};

template <typename T, typename U>
inline bool operator == (const std_erase_on_dealloc<T>&, const std_erase_on_dealloc<U>&) {
    return true;
}

template <typename T, typename U>
inline bool operator != (const std_erase_on_dealloc<T>& a, const std_erase_on_dealloc<U>& b) {
    return !(a == b);
}


/*
 * TODO replace with:
 *
 *  template <typename T>
 *  using SafeBuffer = std::vector<T, erase_on_dealloc<T>>;
 *
 *  typedef SafeBuffer<unsigned char> RawBuffer
 *
 * when gcc 4.7/4.8 is available.
 */
template <typename T>
struct SafeBuffer {
    typedef std::vector<T, std_erase_on_dealloc<T>> Type;
};

// used to pass password and raw key data
typedef SafeBuffer<unsigned char>::Type RawBuffer;

} // namespace CKM

#endif //_SAFE_BUFFER_H_
