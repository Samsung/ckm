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
 */
/*
 * @file        socket-manager.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of SocketManager.
 */

#include <set>

#include <signal.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/smack.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include <systemd/sd-daemon.h>

#include <dpl/log/log.h>
#include <dpl/assert.h>

#include <smack-check.h>
#include <socket-manager.h>

namespace {

const time_t SOCKET_TIMEOUT = 20;

int getCredentialsFromSocket(int sock, CKM::Credentials &cred) {
    CKM::Credentials credentials;
    std::vector<char> result(1);
    socklen_t length = 1;
    ucred peerCred;

    if ((0 > getsockopt(sock, SOL_SOCKET, SO_PEERSEC, result.data(), &length))
        && errno != ERANGE)
    {
        LogError("getsockopt failed");
        return -1;
    }

    result.resize(length);

    if (0 > getsockopt(sock, SOL_SOCKET, SO_PEERSEC, result.data(), &length)) {
        LogError("getsockopt failed");
        return -1;
    }

    length = sizeof(ucred);

    if (0 > getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peerCred, &length)) {
        LogError("getsockopt failed");
        return -1;
    }

    result.push_back('\0');
    cred.smackLabel = result.data();
    cred.uid = peerCred.uid;
    return 0;
}

} // namespace anonymous

namespace CKM {

struct DummyService : public GenericSocketService {
    ServiceDescriptionVector GetServiceDescription() {
        return ServiceDescriptionVector();
    }
    void Event(const AcceptEvent &event) { (void)event; }
    void Event(const WriteEvent &event) { (void)event; }
    void Event(const ReadEvent &event) { (void)event; }
    void Event(const CloseEvent &event) { (void)event; }
};

struct SignalService : public GenericSocketService {
    int GetDescriptor() {
        LogInfo("set up");
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL))
            return -1;
        return signalfd(-1, &mask, 0);
    }

    ServiceDescriptionVector GetServiceDescription() {
        return ServiceDescriptionVector();
    }

    void Event(const AcceptEvent &event) { (void)event; } // not supported
    void Event(const WriteEvent &event) { (void)event; }  // not supported
    void Event(const CloseEvent &event) { (void)event; }  // not supported

    void Event(const ReadEvent &event) {
        LogDebug("Get signal information");

        if(sizeof(struct signalfd_siginfo) != event.rawBuffer.size()) {
            LogError("Wrong size of signalfd_siginfo struct. Expected: "
                << sizeof(signalfd_siginfo) << " Get: "
                << event.rawBuffer.size());
            return;
        }

        signalfd_siginfo *siginfo = (signalfd_siginfo*)(&(event.rawBuffer[0]));

        if (siginfo->ssi_signo == SIGTERM) {
            LogInfo("Got signal: SIGTERM");
            static_cast<SocketManager*>(m_serviceManager)->MainLoopStop();
            return;
        }

        LogInfo("This should not happend. Got signal: " << siginfo->ssi_signo);
    }
};

SocketManager::SocketDescription&
SocketManager::CreateDefaultReadSocketDescription(int sock, bool timeout)
{
    if ((int)m_socketDescriptionVector.size() <= sock)
        m_socketDescriptionVector.resize(sock+20);

    auto &desc = m_socketDescriptionVector[sock];
    desc.isListen = false;
    desc.isOpen = true;
    desc.interfaceID = 0;
    desc.service = NULL;
    desc.counter = ++m_counter;

    if (timeout) {
        desc.timeout = time(NULL) + SOCKET_TIMEOUT;
        if (false == desc.isTimeout) {
            Timeout tm;
            tm.time = desc.timeout;
            tm.sock = sock;
            m_timeoutQueue.push(tm);
        }
    }

    desc.isTimeout = timeout;

    FD_SET(sock, &m_readSet);
    m_maxDesc = sock > m_maxDesc ? sock : m_maxDesc;
    return desc;
}

SocketManager::SocketManager()
  : m_maxDesc(0)
  , m_counter(0)
{
    FD_ZERO(&m_readSet);
    FD_ZERO(&m_writeSet);
    if (-1 == pipe(m_notifyMe)) {
        int err = errno;
        ThrowMsg(Exception::InitFailed, "Error in pipe: " << strerror(err));
    }
    LogInfo("Pipe: Read desc: " << m_notifyMe[0] << " Write desc: " << m_notifyMe[1]);

    auto &desc = CreateDefaultReadSocketDescription(m_notifyMe[0], false);
    desc.service = new DummyService;

    // std::thread bases on pthread so this should work fine
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // add support for TERM signal (passed from systemd)
    auto *signalService = new SignalService;
    signalService->SetSocketManager(this);
    int filefd = signalService->GetDescriptor();
    if (-1 == filefd) {
        LogError("Error in SignalService.GetDescriptor()");
        delete signalService;
    } else {
        auto &desc2 = CreateDefaultReadSocketDescription(filefd, false);
        desc2.service = signalService;
        LogInfo("SignalService mounted on " << filefd << " descriptor");
    }
}

SocketManager::~SocketManager() {
    std::set<GenericSocketService*> serviceMap;

    // Find all services. Set is used to remove duplicates.
    // In this implementation, services are not able to react in any way.
    for (size_t i=0; i < m_socketDescriptionVector.size(); ++i)
        if (m_socketDescriptionVector[i].isOpen)
            serviceMap.insert(m_socketDescriptionVector[i].service);

    // Time to destroy all services.
    for(auto it = serviceMap.begin(); it != serviceMap.end(); ++it) {
        LogDebug("delete " << (void*)(*it));
        delete *it;
    }

    for (size_t i = 0; i < m_socketDescriptionVector.size(); ++i)
        if (m_socketDescriptionVector[i].isOpen)
            close(i);

    // All socket except one were closed. Now pipe input must be closed.
    close(m_notifyMe[1]);
}

void SocketManager::ReadyForAccept(int sock) {
    struct sockaddr_un clientAddr;
    unsigned int clientLen = sizeof(clientAddr);
    int client = accept4(sock, (struct sockaddr*) &clientAddr, &clientLen, SOCK_NONBLOCK);
//    LogInfo("Accept on sock: " << sock << " Socket opended: " << client);
    if (-1 == client) {
        int err = errno;
        LogDebug("Error in accept: " << strerror(err));
        return;
    }

    Credentials peerCred;
    if (0 > getCredentialsFromSocket(client, peerCred)) {
        LogDebug("Error in getCredentialsFromSocket. Socket closed.");
        TEMP_FAILURE_RETRY(close(client));
        return;
    }

    auto &desc = CreateDefaultReadSocketDescription(client, true);
    desc.interfaceID = m_socketDescriptionVector[sock].interfaceID;
    desc.service = m_socketDescriptionVector[sock].service;

    GenericSocketService::AcceptEvent event;
    event.connectionID.sock = client;
    event.connectionID.counter = desc.counter;
    event.interfaceID = desc.interfaceID;
    event.credentials = peerCred;
    desc.service->Event(event);
}

void SocketManager::ReadyForRead(int sock) {
    if (m_socketDescriptionVector[sock].isListen) {
        ReadyForAccept(sock);
        return;
    }

    GenericSocketService::ReadEvent event;
    event.connectionID.sock = sock;
    event.connectionID.counter = m_socketDescriptionVector[sock].counter;
    event.rawBuffer.resize(4096);

    auto &desc = m_socketDescriptionVector[sock];
    desc.timeout = time(NULL) + SOCKET_TIMEOUT;

    ssize_t size = read(sock, &event.rawBuffer[0], 4096);

    if (size == 0) {
        CloseSocket(sock);
    } else if (size >= 0) {
        event.rawBuffer.resize(size);
        desc.service->Event(event);
    } else if (size == -1) {
        int err = errno;
        switch(err) {
            case EAGAIN:
            case EINTR:
                break;
            default:
                LogDebug("Reading sock error: " << strerror(err));
                CloseSocket(sock);
        }
    }
}

void SocketManager::ReadyForWriteBuffer(int sock) {
    auto &desc = m_socketDescriptionVector[sock];
    size_t size = desc.rawBuffer.size();
    ssize_t result = write(sock, &desc.rawBuffer[0], size);
    if (result == -1) {
        int err = errno;
        switch(err) {
        case EAGAIN:
        case EINTR:
            // select will trigger write once again, nothing to do
            break;
        case EPIPE:
        default:
            LogDebug("Error during write: " << strerror(err));
            CloseSocket(sock);
            break;
        }
        return; // We do not want to propagate error to next layer
    }

    desc.rawBuffer.erase(desc.rawBuffer.begin(), desc.rawBuffer.begin()+result);

    desc.timeout = time(NULL) + SOCKET_TIMEOUT;

    if (desc.rawBuffer.empty())
        FD_CLR(sock, &m_writeSet);

    GenericSocketService::WriteEvent event;
    event.connectionID.sock = sock;
    event.connectionID.counter = desc.counter;
    event.size = result;
    event.left = desc.rawBuffer.size();

    desc.service->Event(event);
}

void SocketManager::ReadyForWrite(int sock) {
        ReadyForWriteBuffer(sock);
}

void SocketManager::MainLoop() {
    // remove evironment values passed by systemd
    // uncomment it after removing old security-server code
    // sd_listen_fds(1);

    // Daemon is ready to work.
    sd_notify(0, "READY=1");

    m_working = true;
    while(m_working) {
        fd_set readSet = m_readSet;
        fd_set writeSet = m_writeSet;

        timeval localTempTimeout;
        timeval *ptrTimeout = &localTempTimeout;

        // I need to extract timeout from priority_queue.
        // Timeout in priority_queue may be deprecated.
        // I need to find some actual one.
        while(!m_timeoutQueue.empty()) {
            auto &top = m_timeoutQueue.top();
            auto &desc = m_socketDescriptionVector[top.sock];

            if (top.time == desc.timeout) {
                // This timeout matches timeout from socket.
                // It can be used.
                break;
            } else {
                // This socket was used after timeout in priority queue was set up.
                // We need to update timeout and find some useable one.
                Timeout tm = { desc.timeout , top.sock};
                m_timeoutQueue.pop();
                m_timeoutQueue.push(tm);
            }
        }

        if (m_timeoutQueue.empty()) {
            LogDebug("No usaable timeout found.");
            ptrTimeout = NULL; // select will wait without timeout
        } else {
            time_t currentTime = time(NULL);
            auto &pqTimeout = m_timeoutQueue.top();

            // 0 means that select won't block and socket will be closed ;-)
            ptrTimeout->tv_sec =
              currentTime < pqTimeout.time ? pqTimeout.time - currentTime : 0;
            ptrTimeout->tv_usec = 0;
//            LogDebug("Set up timeout: " << (int)ptrTimeout->tv_sec
//                << " seconds. Socket: " << pqTimeout.sock);
        }

        int ret = select(m_maxDesc+1, &readSet, &writeSet, NULL, ptrTimeout);

        if (0 == ret) { // timeout
            Assert(!m_timeoutQueue.empty());

            Timeout pqTimeout = m_timeoutQueue.top();
            m_timeoutQueue.pop();

            auto &desc = m_socketDescriptionVector[pqTimeout.sock];

            if (!desc.isTimeout || !desc.isOpen) {
                // Connection was closed. Timeout is useless...
                desc.isTimeout = false;
                continue;
            }

            if (pqTimeout.time < desc.timeout) {
                // Is it possible?
                // This socket was used after timeout. We need to update timeout.
                pqTimeout.time = desc.timeout;
                m_timeoutQueue.push(pqTimeout);
                continue;
            }

            // timeout from m_timeoutQueue matches with socket.timeout
            // and connection is open. Time to close it!
            // Putting new timeout in queue here is pointless.
            desc.isTimeout = false;
            CloseSocket(pqTimeout.sock);

            // All done. Now we should process next select ;-)
            continue;
        }

        if (-1 == ret) {
            switch(errno) {
            case EINTR:
                LogDebug("EINTR in select");
                break;
            default:
                int err = errno;
                LogError("Error in select: " << strerror(err));
                return;
            }
            continue;
        }
        for(int i = 0; i<m_maxDesc+1 && ret; ++i) {
            if (FD_ISSET(i, &readSet)) {
                ReadyForRead(i);
                --ret;
            }
            if (FD_ISSET(i, &writeSet)) {
                ReadyForWrite(i);
                --ret;
            }
        }
        ProcessQueue();
    }
}

void SocketManager::MainLoopStop()
{
    m_working = false;
    NotifyMe();
}

int SocketManager::GetSocketFromSystemD(
    const GenericSocketService::ServiceDescription &desc)
{
    int fd;

    // TODO optimalization - do it once in object constructor
    //                       and remember all information path->sockfd
    int n = sd_listen_fds(0);

    LogInfo("sd_listen_fds returns: " << n);

    if (n < 0) {
        LogError("Error in sd_listend_fds");
        ThrowMsg(Exception::InitFailed, "Error in sd_listend_fds");
    }

    for(fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START+n; ++fd) {
        if (0 < sd_is_socket_unix(fd, SOCK_STREAM, 1,
                                  desc.serviceHandlerPath.c_str(), 0))
        {
            LogInfo("Useable socket " << desc.serviceHandlerPath <<
                " was passed by SystemD under descriptor " << fd);
            return fd;
        }
    }
    LogError("No useable sockets were passed by systemd.");
    return -1;
}

int SocketManager::CreateDomainSocketHelp(
    const GenericSocketService::ServiceDescription &desc)
{
    int sockfd;

    if (-1 == (sockfd = socket(AF_UNIX, SOCK_STREAM, 0))) {
        int err = errno;
        LogError("Error in socket: " << strerror(err));
        ThrowMsg(Exception::InitFailed, "Error in socket: " << strerror(err));
    }

    if (smack_check()) {
        LogInfo("Set up smack label: " << desc.smackLabel);

        if (0 != smack_fsetlabel(sockfd, desc.smackLabel.c_str(), SMACK_LABEL_IPIN)) {
            LogError("Error in smack_fsetlabel");
            ThrowMsg(Exception::InitFailed, "Error in smack_fsetlabel");
        }
    } else {
        LogInfo("No smack on platform. Socket won't be securied with smack label!");
    }

    int flags;
    if (-1 == (flags = fcntl(sockfd, F_GETFL, 0)))
        flags = 0;

    if (-1 == fcntl(sockfd, F_SETFL, flags | O_NONBLOCK)) {
        int err = errno;
        close(sockfd);
        LogError("Error in fcntl: " << strerror(err));
        ThrowMsg(Exception::InitFailed, "Error in fcntl: " << strerror(err));
    }

    sockaddr_un serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sun_family = AF_UNIX;
    strcpy(serverAddress.sun_path, desc.serviceHandlerPath.c_str());
    unlink(serverAddress.sun_path);

    mode_t originalUmask;
    originalUmask = umask(0);

    if (-1 == bind(sockfd, (struct sockaddr*)&serverAddress, sizeof(serverAddress))) {
        int err = errno;
        close(sockfd);
        LogError("Error in bind: " << strerror(err));
        ThrowMsg(Exception::InitFailed, "Error in bind: " << strerror(err));
    }

    umask(originalUmask);

    if (-1 == listen(sockfd, 5)) {
        int err = errno;
        close(sockfd);
        LogError("Error in listen: " << strerror(err));
        ThrowMsg(Exception::InitFailed, "Error in listen: " << strerror(err));
    }

    return sockfd;
}

void SocketManager::CreateDomainSocket(
    GenericSocketService *service,
    const GenericSocketService::ServiceDescription &desc)
{
    int sockfd = GetSocketFromSystemD(desc);
    if (-1 == sockfd)
        sockfd = CreateDomainSocketHelp(desc);

    auto &description = CreateDefaultReadSocketDescription(sockfd, false);

    description.isListen = true;
    description.interfaceID = desc.interfaceID;
    description.service = service;

    LogDebug("Listen on socket: " << sockfd <<
        " Handler: " << desc.serviceHandlerPath.c_str());
}

void SocketManager::RegisterSocketService(GenericSocketService *service) {
    service->SetSocketManager(this);
    auto serviceVector = service->GetServiceDescription();
    Try {
        for (auto iter = serviceVector.begin(); iter != serviceVector.end(); ++iter)
            CreateDomainSocket(service, *iter);
    } Catch (Exception::Base) {
        for (int i =0; i < (int)m_socketDescriptionVector.size(); ++i)
        {
            auto &desc = m_socketDescriptionVector[i];
            if (desc.service == service && desc.isOpen) {
                close(i);
                desc.isOpen = false;
            }
        }
        ReThrow(Exception::Base);
    }
}

void SocketManager::Close(ConnectionID connectionID) {
    {
        std::lock_guard<std::mutex> ulock(m_eventQueueMutex);
        m_closeQueue.push(connectionID);
    }
    NotifyMe();
}

void SocketManager::Write(ConnectionID connectionID, const RawBuffer &rawBuffer) {
    WriteBuffer buffer;
    buffer.connectionID = connectionID;
    buffer.rawBuffer = rawBuffer;
    {
        std::lock_guard<std::mutex> ulock(m_eventQueueMutex);
        m_writeBufferQueue.push(buffer);
    }
    NotifyMe();
}

void SocketManager::NotifyMe() {
    TEMP_FAILURE_RETRY(write(m_notifyMe[1], "You have message ;-)", 1));
}

void SocketManager::ProcessQueue() {
    WriteBuffer buffer;
    {
        std::lock_guard<std::mutex> ulock(m_eventQueueMutex);
        while (!m_writeBufferQueue.empty()) {
            buffer = m_writeBufferQueue.front();
            m_writeBufferQueue.pop();

            auto &desc = m_socketDescriptionVector[buffer.connectionID.sock];

            if (!desc.isOpen) {
                LogDebug("Received packet for write but connection is closed. Packet ignored!");
                continue;
            }

            if (desc.counter != buffer.connectionID.counter)
            {
                LogDebug("Received packet for write but counter is broken. Packet ignored!");
                continue;
            }

            std::copy(
                buffer.rawBuffer.begin(),
                buffer.rawBuffer.end(),
                std::back_inserter(desc.rawBuffer));

            FD_SET(buffer.connectionID.sock, &m_writeSet);
        }

    }

    while (1) {
        ConnectionID connection;
        {
            std::lock_guard<std::mutex> ulock(m_eventQueueMutex);
            if (m_closeQueue.empty())
                return;
            connection = m_closeQueue.front();
            m_closeQueue.pop();
        }

        if (!m_socketDescriptionVector[connection.sock].isOpen)
            continue;

        if (connection.counter != m_socketDescriptionVector[connection.sock].counter)
            continue;

        CloseSocket(connection.sock);
    }
}

void SocketManager::CloseSocket(int sock) {
//    LogInfo("Closing socket: " << sock);
    auto &desc = m_socketDescriptionVector[sock];

    if (!(desc.isOpen)) {
        // This may happend when some information was waiting for write to the
        // socket and in the same time socket was closed by the client.
        LogError("Socket " << sock << " is not open. Nothing to do!");
        return;
    }

    GenericSocketService::CloseEvent event;
    event.connectionID.sock = sock;
    event.connectionID.counter = desc.counter;
    auto service = desc.service;

    desc.isOpen = false;
    desc.service = NULL;
    desc.interfaceID = -1;
    desc.rawBuffer.clear();

    if (service)
        service->Event(event);
    else
        LogError("Critical! Service is NULL! This should never happend!");

    TEMP_FAILURE_RETRY(close(sock));
    FD_CLR(sock, &m_readSet);
    FD_CLR(sock, &m_writeSet);
}

} // namespace CKM
