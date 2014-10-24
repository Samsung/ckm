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
 * @file        client-common.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file is implementation of client-common functions.
 */

#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <dpl/errno_string.h>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <message-buffer.h>

#include <ckm/ckm-error.h>

#include <client-common.h>

IMPLEMENT_SAFE_SINGLETON(CKM::Log::LogSystem);

namespace {

const int POLL_TIMEOUT = 8000;

void centKeyClientEnableLogSystem(void) {
    CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CKM_CLIENT");
}

int waitForSocket(int sock, int event, int timeout) {
    int retval;
    pollfd desc[1];
    desc[0].fd = sock;
    desc[0].events = event;

    while((-1 == (retval = poll(desc, 1, timeout))) && (errno == EINTR)) {
        timeout >>= 1;
        errno = 0;
    }

    if (0 == retval) {
        LogDebug("Poll timeout");
    } else if (-1 == retval) {
        int err = errno;
        LogError("Error in poll: " << CKM::GetErrnoString(err));
    }
    return retval;
}

} // namespace anonymous

namespace CKM {


int connectSocket(int& sock, char const * const interface) {
    sockaddr_un clientAddr;
    int flags;

    if (sock != -1) // guard
        close(sock);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        int err = errno;
        LogError("Error creating socket: " << GetErrnoString(err));
        return CKM_API_ERROR_SOCKET;
    }

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0 ||
        fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        int err = errno;
        LogError("Error in fcntl: " << GetErrnoString(err));
        return CKM_API_ERROR_SOCKET;
    }

    memset(&clientAddr, 0, sizeof(clientAddr));

    clientAddr.sun_family = AF_UNIX;

    if (strlen(interface) >= sizeof(clientAddr.sun_path)) {
        LogError("Error: interface name " << interface << "is too long. Max len is:" <<
                 sizeof(clientAddr.sun_path));
        return CKM_API_ERROR_SOCKET;
    }

    strcpy(clientAddr.sun_path, interface);

    LogDebug("ClientAddr.sun_path = " << interface);

    int retval = TEMP_FAILURE_RETRY(
        connect(sock, (struct sockaddr*)&clientAddr, SUN_LEN(&clientAddr)));
    if ((retval == -1) && (errno == EINPROGRESS)) {
        if (0 >= waitForSocket(sock, POLLOUT, POLL_TIMEOUT)) {
            LogError("Error in waitForSocket.");
            return CKM_API_ERROR_SOCKET;
        }
        int error = 0;
        socklen_t len = sizeof(error);
        retval = getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);

        if (-1 == retval) {
            int err = errno;
            LogError("Error in getsockopt: " << GetErrnoString(err));
            return CKM_API_ERROR_SOCKET;
        }

        if (error == EACCES) {
            LogError("Access denied");
            return CKM_API_ERROR_ACCESS_DENIED;
        }

        if (error != 0) {
            LogError("Error in connect: " << GetErrnoString(error));
            return CKM_API_ERROR_SOCKET;
        }

        return CKM_API_SUCCESS;
    }

    if (-1 == retval) {
        int err = errno;
        LogError("Error connecting socket: " << GetErrnoString(err));
        if (err == EACCES)
            return CKM_API_ERROR_ACCESS_DENIED;
        return CKM_API_ERROR_SOCKET;
    }

    return CKM_API_SUCCESS;
}

int sendToServer(char const * const interface, const RawBuffer &send, MessageBuffer &recv) {
    int ret;
    SockRAII sock;
    ssize_t done = 0;
    char buffer[2048];

    if (CKM_API_SUCCESS != (ret = sock.Connect(interface))) {
        LogError("Error in SockRAII");
        return ret;
    }

    while ((send.size() - done) > 0) {
        if (0 >= waitForSocket(sock.Get(), POLLOUT, POLL_TIMEOUT)) {
            LogError("Error in poll(POLLOUT)");
            return CKM_API_ERROR_SOCKET;
        }
        ssize_t temp = TEMP_FAILURE_RETRY(write(sock.Get(), &send[done], send.size() - done));
        if (-1 == temp) {
            int err = errno;
            LogError("Error in write: " << GetErrnoString(err));
            return CKM_API_ERROR_SOCKET;
        }
        done += temp;
    }

    do {
        if (0 >= waitForSocket(sock.Get(), POLLIN, POLL_TIMEOUT)) {
            LogError("Error in poll(POLLIN)");
            return CKM_API_ERROR_SOCKET;
        }
        ssize_t temp = TEMP_FAILURE_RETRY(read(sock.Get(), buffer, 2048));
        if (-1 == temp) {
            int err = errno;
            LogError("Error in read: " << GetErrnoString(err));
            return CKM_API_ERROR_SOCKET;
        }

        if (0 == temp) {
            LogError("Read return 0/Connection closed by server(?)");
            return CKM_API_ERROR_SOCKET;
        }

        RawBuffer raw(buffer, buffer+temp);
        recv.Push(raw);
    } while(!recv.Ready());
    return CKM_API_SUCCESS;
}

int try_catch(const std::function<int()>& func)
{
    try {
        return func();
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("CKM::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return CKM_API_ERROR_UNKNOWN;
}

void try_catch_async(const std::function<void()>& func, const std::function<void(int)>& error)
{
    try {
        func();
    } catch (const MessageBuffer::Exception::Base& e) {
        LogError("CKM::MessageBuffer::Exception " << e.DumpToString());
        error(CKM_API_ERROR_BAD_REQUEST);
    } catch (const std::exception& e) {
        LogError("STD exception " << e.what());
        error(CKM_API_ERROR_UNKNOWN);
    } catch (...) {
        LogError("Unknown exception occured");
        error(CKM_API_ERROR_UNKNOWN);
    }
}

} // namespace CKM

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
    centKeyClientEnableLogSystem();
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{

}

