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

#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <message-buffer.h>

#include <ckm/ckm-error.h>

IMPLEMENT_SAFE_SINGLETON(CKM::Log::LogSystem);

namespace {

const int POLL_TIMEOUT = 4000;

void centKeyClientEnableLogSystem(void) {
    CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CENT_KEY_CLIENT");
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
        LogError("Error in poll: " << strerror(err));
    }
    return retval;
}

class SockRAII {
public:
    SockRAII()
      : m_sock(-1)
    {}

    virtual ~SockRAII() {
        if (m_sock > -1)
            close(m_sock);
    }

    int Connect(char const * const interface) {
        sockaddr_un clientAddr;
        int flags;

        if (m_sock != -1) // guard
            close(m_sock);

        m_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (m_sock < 0) {
            int err = errno;
            LogError("Error creating socket: " << strerror(err));
            return KEY_MANAGER_API_ERROR_SOCKET;
        }

        if ((flags = fcntl(m_sock, F_GETFL, 0)) < 0 ||
            fcntl(m_sock, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            int err = errno;
            LogError("Error in fcntl: " << strerror(err));
            return KEY_MANAGER_API_ERROR_SOCKET;
        }

        memset(&clientAddr, 0, sizeof(clientAddr));

        clientAddr.sun_family = AF_UNIX;

        if (strlen(interface) >= sizeof(clientAddr.sun_path)) {
            LogError("Error: interface name " << interface << "is too long. Max len is:" << sizeof(clientAddr.sun_path));
            return KEY_MANAGER_API_ERROR_SOCKET;
        }

        strcpy(clientAddr.sun_path, interface);

        LogDebug("ClientAddr.sun_path = " << interface);

        int retval = TEMP_FAILURE_RETRY(connect(m_sock, (struct sockaddr*)&clientAddr, SUN_LEN(&clientAddr)));
        if ((retval == -1) && (errno == EINPROGRESS)) {
            if (0 >= waitForSocket(m_sock, POLLIN, POLL_TIMEOUT)) {
                LogError("Error in waitForSocket.");
                return KEY_MANAGER_API_ERROR_SOCKET;
            }
            int error = 0;
            size_t len = sizeof(error);
            retval = getsockopt(m_sock, SOL_SOCKET, SO_ERROR, &error, &len);

            if (-1 == retval) {
                int err = errno;
                LogError("Error in getsockopt: " << strerror(err));
                return KEY_MANAGER_API_ERROR_SOCKET;
            }

            if (error == EACCES) {
                LogError("Access denied");
                return KEY_MANAGER_API_ERROR_ACCESS_DENIED;
            }

            if (error != 0) {
                LogError("Error in connect: " << strerror(error));
                return KEY_MANAGER_API_ERROR_SOCKET;
            }

            return KEY_MANAGER_API_SUCCESS;
        }

        if (-1 == retval) {
            int err = errno;
            LogError("Error connecting socket: " << strerror(err));
            if (err == EACCES)
                return KEY_MANAGER_API_ERROR_ACCESS_DENIED;
            return KEY_MANAGER_API_ERROR_SOCKET;
        }

        return KEY_MANAGER_API_SUCCESS;
    }

    int Get() {
        return m_sock;
    }

private:
    int m_sock;
};

} // namespace anonymous

namespace CKM {


int sendToServer(char const * const interface, const RawBuffer &send, MessageBuffer &recv) {
    int ret;
    SockRAII sock;
    ssize_t done = 0;
    char buffer[2048];

    if (KEY_MANAGER_API_SUCCESS != (ret = sock.Connect(interface))) {
        LogError("Error in SockRAII");
        return ret;
    }

    while ((send.size() - done) > 0) {
        if (0 >= waitForSocket(sock.Get(), POLLOUT, POLL_TIMEOUT)) {
            LogError("Error in poll(POLLOUT)");
            return KEY_MANAGER_API_ERROR_SOCKET;
        }
        ssize_t temp = TEMP_FAILURE_RETRY(write(sock.Get(), &send[done], send.size() - done));
        if (-1 == temp) {
            int err = errno;
            LogError("Error in write: " << strerror(err));
            return KEY_MANAGER_API_ERROR_SOCKET;
        }
        done += temp;
    }

    do {
        if (0 >= waitForSocket(sock.Get(), POLLIN, POLL_TIMEOUT)) {
            LogError("Error in poll(POLLIN)");
            return KEY_MANAGER_API_ERROR_SOCKET;
        }
        ssize_t temp = TEMP_FAILURE_RETRY(read(sock.Get(), buffer, 2048));
        if (-1 == temp) {
            int err = errno;
            LogError("Error in read: " << strerror(err));
            return KEY_MANAGER_API_ERROR_SOCKET;
        }

        if (0 == temp) {
            LogError("Read return 0/Connection closed by server(?)");
            return KEY_MANAGER_API_ERROR_SOCKET;
        }

        RawBuffer raw(buffer, buffer+temp);
        recv.Push(raw);
    } while(!recv.Ready());
    return KEY_MANAGER_API_SUCCESS;
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
    return KEY_MANAGER_API_ERROR_UNKNOWN;
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

