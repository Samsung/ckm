/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        fstream-helper.h
 * @author      Marek Smolinski (m.smolinski@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of fstream-helper
 *
 */

#ifndef CENT_KEY_FSTREAM_ACCESSORS_H
#define CENT_KEY_FSTREAM_ACCESSORS_H

namespace DPL {

/*
 * Bypass lack of public member function to get file
 * descriptor from fstream objects in std
 * This feature is needed for flushing data from kernel space buffer to
 * physical device [fsync(int fd) - syscall] on opened fstream object
*/

template<typename T>
class FstreamAccessors : T::__filebuf_type {
    typedef FstreamAccessors<T> MyType;
public:
    static int GetFd(T &strm) {
        return static_cast<MyType *>(strm.rdbuf())->_M_file.fd();
    }
};

} // namespace DPL

#endif // CENT_KEY_FSTREAM_ACCESSORS_H
