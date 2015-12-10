/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        socket-manager.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       SocketManager implementation.
 */

#ifndef _CENT_KEY_MNG_SOCKET_MANAGER_
#define _CENT_KEY_MNG_SOCKET_MANAGER_

#include <vector>
#include <queue>
#include <string>
#include <mutex>
#include <thread>
#include <functional>

#include <dpl/exception.h>

#include <generic-socket-manager.h>
#include <service-messages.h>

namespace CKM {

class Cynara;

class SocketManager : public GenericSocketManager {
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, InitFailed)
    };

    SocketManager();
    virtual ~SocketManager();
    virtual void MainLoop();
    virtual void MainLoopStop();

    virtual void CynaraSocket(int oldFd, int newFd, bool isRW);
    void SecurityStatus(int sock, int counter, bool allowed);

    virtual void RegisterSocketService(GenericSocketService *service);
    virtual void Close(ConnectionID connectionID);
    virtual void Write(ConnectionID connectionID, const RawBuffer &rawBuffer);
    virtual void SecurityCheck(ConnectionID connectionID);

protected:
    void CreateDomainSocket(
        GenericSocketService *service,
        const GenericSocketService::ServiceDescription &desc);
    int CreateDomainSocketHelp(
        const GenericSocketService::ServiceDescription &desc);
    int GetSocketFromSystemD(
        const GenericSocketService::ServiceDescription &desc);

    void ReadyForRead(int sock);
    void ReadyForWrite(int sock);
    void ReadyForAccept(int sock);
    void ProcessQueue(void);
    void NotifyMe(void);
    void CloseSocket(int sock);

    struct SocketDescription {
        bool isOpen() { return m_flags & OPEN; }
        bool isListen() { return m_flags & LISTEN; }
        bool isCynara() { return m_flags & CYNARA; }
        bool isTimeout() { return m_flags & TIMEOUT; }
        void setOpen(bool isSet) { isSet ? m_flags |= OPEN : m_flags &= ~OPEN; }
        void setListen(bool isSet) { isSet ? m_flags |= LISTEN : m_flags &= ~LISTEN; }
        void setCynara(bool isSet) { isSet ? m_flags |= CYNARA : m_flags &= ~CYNARA; }
        void setTimeout(bool isSet) { isSet ? m_flags |= TIMEOUT : m_flags &= ~TIMEOUT; }

        InterfaceID interfaceID;
        GenericSocketService *service;
        time_t timeout;
        RawBuffer rawBuffer;
        int counter;
        std::string cynaraPrivilege;
        std::string cynaraUser;
        std::string cynaraClient;

        SocketDescription()
          : interfaceID(-1)
          , service(NULL)
          , m_flags(0)
        {
        }

    private:
        static const char LISTEN  = 1 << 0;
        static const char OPEN    = 1 << 1;
        static const char CYNARA  = 1 << 2;
        static const char TIMEOUT = 1 << 3;
        int m_flags;
    };

    SocketDescription& CreateDefaultReadSocketDescription(int sock, bool timeout);

    typedef std::vector<SocketDescription> SocketDescriptionVector;

    // support for generic event Queue
    typedef std::function<void(void)> EventFunction;
    template <typename E>
    void AddEvent(E event)
    {
        CreateEvent([this, event]() {this->Handle(event);});
    }
    void CreateEvent(EventFunction fun);

    struct WriteEvent {
        ConnectionID connectionID;
        RawBuffer rawBuffer;
    };

    struct CloseEvent : public ConnectionID {};
    struct SecurityEvent : public ConnectionID {};

    void Handle(const WriteEvent &event);
    void Handle(const CloseEvent &event);
    void Handle(const SecurityEvent &event);
    // support for generic event Queue

    struct Timeout {
        time_t time;
        int sock;
        bool operator<(const Timeout &second) const
        {
            return time > second.time; // mininum first!
        }
    };

    SocketDescriptionVector m_socketDescriptionVector;
    fd_set m_readSet;
    fd_set m_writeSet;
    int m_maxDesc;
    bool m_working;
    std::mutex m_eventQueueMutex;
    std::queue<EventFunction> m_eventQueue;
    int m_notifyMe[2];
    int m_counter;
    std::priority_queue<Timeout> m_timeoutQueue;
    CommMgr m_commMgr;
    std::unique_ptr<Cynara> m_cynara;
};

} // namespace CKM

#endif // _CENT_KEY_MNG_SOCKET_MANAGER_
