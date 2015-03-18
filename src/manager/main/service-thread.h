/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file        service-thread.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of threads.
 */

#ifndef _CENT_KEY_SERVICE_THREAD_
#define _CENT_KEY_SERVICE_THREAD_

#include <cassert>
#include <queue>
#include <mutex>
#include <thread>
#include <memory>
#include <functional>
#include <condition_variable>

#include <cstdio>

#include <dpl/exception.h>

#include "generic-event.h"

namespace CKM {

class ServiceThread {
public:
    typedef std::function<void(void)> EventDescription;
    enum class State {
        NoThread,
        Work,
    };

    ServiceThread()
      : m_state(State::NoThread)
      , m_quit(false)
    {}

    void Create() {
        assert(m_state == State::NoThread);
        m_thread = std::thread(ThreadLoopStatic, this);
        m_state = State::Work;
    }

    void Join() {
        assert(m_state != State::NoThread);
        {
            std::lock_guard<std::mutex> lock(m_eventQueueMutex);
            m_quit = true;
            m_waitCondition.notify_one();
        }
        m_thread.join();
        m_state = State::NoThread;
    }

    virtual ~ServiceThread()
    {
        if (m_state != State::NoThread)
            Join();
    }

protected:
    /*
     * This function is always called from ThreadService::ThreadEvent where fun
     * is created as a temporary object and therefore will not be copied.
     */
    void CreateEvent(std::function<void(void)> fun)
    {
        EventDescription description;
        description = std::move(fun);
        {
            std::lock_guard<std::mutex> lock(m_eventQueueMutex);
            m_eventQueue.push(description);
        }
        m_waitCondition.notify_one();
    }

    static void ThreadLoopStatic(ServiceThread *ptr) {
        ptr->ThreadLoop();
    }

    void ThreadLoop(){
        for (;;) {
            EventDescription description;
            {
                std::unique_lock<std::mutex> ulock(m_eventQueueMutex);
                if (m_quit)
                    return;
                if (!m_eventQueue.empty()) {
                    description = m_eventQueue.front();
                    m_eventQueue.pop();
                } else {
                    m_waitCondition.wait(ulock);
                }
            }

            if (description) {
                UNHANDLED_EXCEPTION_HANDLER_BEGIN
                {
                    description();
                }
                UNHANDLED_EXCEPTION_HANDLER_END
            }
        }
    }

    std::thread m_thread;
    std::mutex m_eventQueueMutex;
    std::queue<EventDescription> m_eventQueue;
    std::condition_variable m_waitCondition;

    State m_state;
    bool m_quit;
};

} // namespace CKM

#endif // _CENT_KEY_SERVICE_THREAD_
