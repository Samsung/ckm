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
 * @file       connection-thread.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <thread>
#include <mutex>
#include <string>
#include <dpl/exception.h>
#include <noncopyable.h>
#include <client-common.h>
#include <async-request.h>
#include <descriptor-set.h>

namespace CKM {

class ConnectionThread
{
public:
    DECLARE_EXCEPTION_TYPE(CKM::Exception, PipeError)

    ConnectionThread();
    virtual ~ConnectionThread();

    NONCOPYABLE(ConnectionThread);

    void run();

    void sendMessage(AsyncRequest&& request);

    bool finished() const { return m_finished; }

private:
    void threadLoop();

    void newRequest(int pipe, short revents);

    // reads notification pipe
    void readPipe(int pipe, short revents);

    // Helper class that creates a pipe before thread is started
    class Pipe {
    public:
        Pipe();
        ~Pipe();

        NONCOPYABLE(Pipe);

        void notify();
        int output() const { return m_pipe[0]; }

    private:
        int m_pipe[2];
    };
    // shared vars
    Pipe m_pipe;
    AsyncRequest::Queue m_waitingReqs;
    std::mutex m_mutex;
    bool m_join;
    bool m_finished;

    // parent thread vars
    std::thread m_thread;

    // child thread vars
    DescriptorSet m_descriptors;
};

} /* namespace CKM */
