/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       message-service.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <mutex>
#include <list>
#include <utility>
#include <thread-service.h>
#include <noncopyable.h>
#include <dpl/log/log.h>

namespace CKM {

/*
 * MessageService framework is a wrapper for inter service communication with use of
 * CommunicationManager. It allows registering a service as a listener in CommunicationManager and
 * provides thread safe message handling. The message received from communication manager in
 * SENDER THREAD is passed to RECEIVER THREAD. The RECEIVER THREAD is notified with
 * ServiceThread::CreateEvent which in turn calls provided callback in this thread.
 */

template <typename ...Msgs>
class MessageService;


// aggregating template
template <typename Msg, typename ...Msgs>
class MessageService<Msg, Msgs...> : public MessageService<Msg>, public MessageService<Msgs...>
{
protected:
    // RECEIVER THREAD
    template <typename Mgr>
    void Register(Mgr& mgr) {
        MessageService<Msg>::Register(mgr);
        MessageService<Msgs...>::Register(mgr);
    }
    // RECEIVER THREAD
    void CheckMessages() {
        MessageService<Msg>::CheckMessages();
        MessageService<Msgs...>::CheckMessages();
    }
};


// single Message type (Msg) handler
template <typename Msg>
class MessageService<Msg>
{
public:
    MessageService() {}
    virtual ~MessageService() {}
    NONCOPYABLE(MessageService);

protected:
    // RECEIVER THREAD: register as a listener of Msg
    template <typename Mgr>
    void Register(Mgr& mgr);

    // SENDER THREAD: notify about new message
    virtual void Notify() = 0;

    // RECEIVER THREAD: check if there are new messages and process each of them
    void CheckMessages();

    // RECEIVER THREAD: process single message
    virtual void ProcessMessage(Msg msg) = 0;

private:
    // SENDER THREAD: add message to the list
    void AddMessage(const Msg& msg);

    std::mutex m_messagesMutex;
    std::list<Msg> m_messages;
};

template <typename Msg>
template <typename Mgr>
void MessageService<Msg>::Register(Mgr& mgr)
{
    mgr.Register<Msg>([this](const Msg& msg) { this->AddMessage(msg); });
}

template <typename Msg>
void MessageService<Msg>::AddMessage(const Msg& msg)
{
    m_messagesMutex.lock();
    m_messages.push_back(msg);
    m_messagesMutex.unlock();
    Notify(); // notify about added message
}

template <typename Msg>
void MessageService<Msg>::CheckMessages()
{
    while(true) {
        m_messagesMutex.lock();
        if (m_messages.empty()) {
            m_messagesMutex.unlock();
            break;
        }
        // move out the first message
        Msg message = std::move(m_messages.front());
        m_messages.pop_front();
        m_messagesMutex.unlock();

        try {
            ProcessMessage(std::move(message));
        } catch(...) {
            LogError("Uncaught exception in ProcessMessage");
        }
    }
}


// thread based service with messages support
template <typename ...Msgs>
class ThreadMessageService : public ThreadService, public MessageService<Msgs...>
{
public:
    ThreadMessageService() {}
    virtual ~ThreadMessageService() {}
    NONCOPYABLE(ThreadMessageService);

    // RECEIVER THREAD: register as a listener of all supported messages
    template <typename Mgr>
    void Register(Mgr& mgr) {
        MessageService<Msgs...>::Register(mgr);
    }

private:
    // SENDER THREAD: adds callback to RECEIVER THREAD event queue and wakes it
    virtual void Notify() {
        CreateEvent([this]() { this->CheckMessages(); });
    }

    // RECEIVER THREAD
    void CheckMessages() {
        MessageService<Msgs...>::CheckMessages();
    }
};

} /* namespace CKM */
