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
 * @file       communication-manager.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <functional>
#include <list>
#include <noncopyable.h>

namespace CKM {

/*
 * class responsible for keeping a list of listeners for given M type of message and notifying them
 */
template <typename M>
class MessageManager
{
public:
    NONCOPYABLE(MessageManager);

    // Listener is an object callable with const M& as argument
    template <typename L>
    void Register(L&& listener)
    {
        m_listeners.push_back(std::move(listener));
    }

    // Sends message of type M to all registered listeners
    // Returns the number of listeners called
    size_t SendMessage(const M& msg) const
    {
        for(auto& it : m_listeners)
            it(msg);
        return m_listeners.size();
    }
protected:
    MessageManager() {}
    // No one is going to destroy this class directly (only via inherited class). Hence no 'virtual'
    ~MessageManager() {}

private:
    std::list<std::function<void(const M&)>> m_listeners;
};

// generic template declaration
template <typename... Args>
struct CommunicationManager;

/*
 * Class that combines MessageManagers of all requested Message types into a single object. Examples
 * can be found in tests (test_msg-manager.cpp)
 */
template <typename First, typename... Args>
struct CommunicationManager<First, Args...> :
    public MessageManager<First>, public CommunicationManager<Args...>
{
public:
    CommunicationManager() {}
    NONCOPYABLE(CommunicationManager);

    // M - message type, L - listener to register
    template <typename M, typename L>
    void Register(L&& listener)
    {
        MessageManager<M>::Register(std::move(listener));
    }

    // M message type
    // Sending a message calls an unknown listener callback on the receiving side. It may throw.
    template <typename M>
    size_t SendMessage(const M& msg) const
    {
        return MessageManager<M>::SendMessage(msg);
    }
};

// stop condition for recursive inheritance
template <>
struct CommunicationManager<> {
};

} /* namespace CKM */
