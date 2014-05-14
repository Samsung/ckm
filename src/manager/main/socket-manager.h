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

#include <dpl/exception.h>

#include <generic-socket-manager.h>

namespace CentralKeyManager {

class SocketManager : public GenericSocketManager {
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(CentralKeyManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, InitFailed)
    };
    SocketManager();
    virtual ~SocketManager();
    virtual void MainLoop();
    virtual void MainLoopStop();

    virtual void RegisterSocketService(GenericSocketService *service);
    virtual void Close(ConnectionID connectionID);
    virtual void Write(ConnectionID connectionID, const RawBuffer &rawBuffer);

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
    void ReadyForWriteBuffer(int sock);
    void ReadyForSendMsg(int sock);
    void ReadyForAccept(int sock);
    void ProcessQueue(void);
    void NotifyMe(void);
    void CloseSocket(int sock);

    struct SocketDescription {
        bool isListen;
        bool isOpen;
        bool isTimeout;
        InterfaceID interfaceID;
        GenericSocketService *service;
        time_t timeout;
        RawBuffer rawBuffer;
        int counter;

        SocketDescription()
          : isListen(false)
          , isOpen(false)
          , isTimeout(false)
          , interfaceID(-1)
          , service(NULL)
        {}
    };

    SocketDescription& CreateDefaultReadSocketDescription(int sock, bool timeout);

    typedef std::vector<SocketDescription> SocketDescriptionVector;

    struct WriteBuffer {
        ConnectionID connectionID;
        RawBuffer rawBuffer;
    };

    struct Timeout {
        time_t time;
        int sock;
        bool operator<(const Timeout &second) const {
            return time > second.time; // mininum first!
        }
    };

    SocketDescriptionVector m_socketDescriptionVector;
    fd_set m_readSet;
    fd_set m_writeSet;
    int m_maxDesc;
    bool m_working;
    std::mutex m_eventQueueMutex;
    std::queue<WriteBuffer> m_writeBufferQueue;
    std::queue<ConnectionID> m_closeQueue;
    int m_notifyMe[2];
    int m_counter;
    std::priority_queue<Timeout> m_timeoutQueue;
};

} // namespace CentralKeyManager

#endif // _CENT_KEY_MNG_SOCKET_MANAGER_
