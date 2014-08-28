/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file       test_watched-thread.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <functional>
#include <thread>
#include <utility>
#include <boost/test/test_tools.hpp>
#include <dpl/exception.h>
#include <noncopyable.h>

// Error handling in threads
DECLARE_EXCEPTION_TYPE(CKM::Exception, ThreadErrorMessage)

template <typename F, typename... Args>
class WatchedThread {
public:
    // can't use rreferences for Args because std::thread needs to copy all arguments
    explicit WatchedThread(F&& function, const Args&... args) :
        m_function(std::move(function)),
        m_thread(&WatchedThread::Wrapper, this, args...)
    {}

    ~WatchedThread() {
        m_thread.join();
        if (!m_error.empty())
            BOOST_FAIL(m_error);
    }

    NONCOPYABLE(WatchedThread);

    WatchedThread(WatchedThread&&) = default;
    WatchedThread& operator=(WatchedThread&&) = default;

protected:

    void Wrapper(const Args&... args) {
        try {
            m_function(args...);
        } catch (const ThreadErrorMessage& e) {
            m_error = e.DumpToString();
        }
    }

    std::string m_error;
    F m_function;
    std::thread m_thread;
};

template <typename F, typename... Args>
WatchedThread<F, Args...> CreateWatchedThread(F&& function, const Args&... args)
{
    return WatchedThread<F, Args...>(std::move(function), args...);
}

#define THREAD_REQUIRE_MESSAGE(expr, message)                \
    do {                                                     \
        if (!(expr))                                         \
            ThrowMsg( ThreadErrorMessage, message);          \
    } while (false);
