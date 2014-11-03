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
#include <ckmc/ckmc-type.h>
#include <protocols.h>
#include <client-common.h>

IMPLEMENT_SAFE_SINGLETON(CKM::Log::LogSystem);

namespace {

const int POLL_TIMEOUT = 600000;

void centKeyClientEnableLogSystem(void) {
    CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CKM_CLIENT");
}

} // namespace anonymous

namespace CKM {

SockRAII::SockRAII() : m_sock(-1) {}

SockRAII::~SockRAII()
{
    disconnect();
}

int SockRAII::connect(const char * interface)
{
    if (!interface) {
        LogError("No valid interface address given.");
        return CKM_API_ERROR_INPUT_PARAM;
    }

    int localSock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (localSock < 0) {
        LogError("Error creating socket: " << CKM::GetErrnoString(errno));
        return CKM_API_ERROR_SOCKET;
    }

    int retCode = connectWrapper(localSock, interface);

    if (retCode != CKM_API_SUCCESS) {
        close(localSock);
        return retCode;
    }

    disconnect();

    m_sock = localSock;

    return CKM_API_SUCCESS;
}

int SockRAII::connectWrapper(int sock, const char *interface) {
    int flags;

    // we need to be sure that socket is in blocking mode
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0 || fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        LogError("Error in fcntl: " << CKM::GetErrnoString(errno));
        return CKM_API_ERROR_SOCKET;
    }

    sockaddr_un clientAddr;
    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sun_family = AF_UNIX;

    if (strlen(interface) >= sizeof(clientAddr.sun_path)) {
        LogError("Error: interface name " << interface << "is too long."
            " Max len is:" << sizeof(clientAddr.sun_path));
        return CKM_API_ERROR_INPUT_PARAM;
    }

    strcpy(clientAddr.sun_path, interface);
    LogDebug("ClientAddr.sun_path = " << interface);

    int retval = TEMP_FAILURE_RETRY(::connect(sock, (struct sockaddr*)&clientAddr, SUN_LEN(&clientAddr)));

    // we don't need to support EINPROGRESS because the socket is in blocking mode
    if(-1 == retval)
    {
        if (errno == EACCES) {
            LogError("Access denied to interface: " << interface);
            return CKM_API_ERROR_ACCESS_DENIED;
        }
        LogError("Error connecting socket: " << CKM::GetErrnoString(errno));
        return CKM_API_ERROR_SOCKET;
    }

    // make the socket non-blocking
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        LogError("Error in fcntl: " << CKM::GetErrnoString(errno));
        return CKM_API_ERROR_SOCKET;
    }

    return CKM_API_SUCCESS;
}

bool SockRAII::isConnected() const {
    return (m_sock > -1);
}

void SockRAII::disconnect() {
    if (isConnected())
        close(m_sock);
    m_sock = -1;
}

int SockRAII::waitForSocket(int event, int timeout)
{
    int retval;
    pollfd desc[1];
    desc[0].fd = m_sock;
    desc[0].events = event;

    while((-1 == (retval = poll(desc, 1, timeout))) && (errno == EINTR)) {
        timeout >>= 1;
        errno = 0;
    }

    if (0 == retval) {
        LogDebug("Poll timeout");
    } else if(-1 == retval) {
        LogError("Error in poll: " << CKM::GetErrnoString(errno));
    }
    return retval;
}

int SockRAII::get() const {
    return m_sock;
}

} // namespace anonymous

namespace CKM {

AliasSupport::AliasSupport(const Alias &alias)
{
    std::size_t separator_pos = alias.rfind(CKM::LABEL_NAME_SEPARATOR);
    if(separator_pos == Alias::npos)
    {
        m_label.clear();
        m_name = alias;
    } else {
        m_label = alias.substr(0, separator_pos);
        m_name = alias.substr(separator_pos + strlen(CKM::LABEL_NAME_SEPARATOR));
    }
}

Alias AliasSupport::merge(const Label &label, const Name &name)
{
    if(label.empty())
        return name;

    std::stringstream output;
    output << label << std::string(CKM::LABEL_NAME_SEPARATOR) << name;
    return output.str();
}

const Name & AliasSupport::getName() const {
    return m_name;
}

const Label & AliasSupport::getLabel() const {
    return m_label;
}

bool AliasSupport::isLabelEmpty() const {
    return m_label.empty();
}

ServiceConnection::ServiceConnection(char const * const service_interface) {
    if(service_interface)
        m_serviceInterface = std::string(service_interface);
}

int ServiceConnection::processRequest( const CKM::RawBuffer &send_buf,
                                       CKM::MessageBuffer &recv_buf) {
    int ec;
    if(CKM_API_SUCCESS != (ec = send(send_buf)))
        return ec;

    return receive(recv_buf);
}

int ServiceConnection::Connect()
{
    // cleanup
    if (isConnected())
        disconnect();

    return SockRAII::connect(m_serviceInterface.c_str());
}

int ServiceConnection::send(const CKM::RawBuffer &send_buf)
{
    if( ! isConnected() )
    {
        int ec;
        if(CKM_API_SUCCESS != (ec = ServiceConnection::Connect()))
        {
            LogError("send failed, connect fail code: " << ec);
            return ec;
        }
    }

    int ec = CKM_API_SUCCESS;
    ssize_t done = 0;
    while((send_buf.size() - done) > 0)
    {
        if( 0 >= waitForSocket(POLLOUT, POLL_TIMEOUT)) {
            LogError("Error in WaitForSocket.");
            ec = CKM_API_ERROR_SOCKET;
            break;
        }

        ssize_t temp = TEMP_FAILURE_RETRY(write(m_sock, &send_buf[done], send_buf.size() - done));
        if(-1 == temp) {
            LogError("Error in write: " << CKM::GetErrnoString(errno));
            ec = CKM_API_ERROR_SOCKET;
            break;
        }

        done += temp;
    }

    if(ec != CKM_API_SUCCESS)
        disconnect();

    return ec;
}

int ServiceConnection::receive(CKM::MessageBuffer &recv_buf)
{
    if( ! isConnected() )
    {
        LogError("Not connected!");
        return CKM_API_ERROR_SOCKET;
    }

    int ec = CKM_API_SUCCESS;
    const size_t c_recv_buf_len = 2048;
    char buffer[c_recv_buf_len];
    do
    {
        if( 0 >= waitForSocket(POLLIN, POLL_TIMEOUT)) {
            LogError("Error in WaitForSocket.");
            ec = CKM_API_ERROR_SOCKET;
            break;
        }

        ssize_t temp = TEMP_FAILURE_RETRY(read(m_sock, buffer, sizeof(buffer)));
        if(-1 == temp) {
            LogError("Error in read: " << CKM::GetErrnoString(errno));
            ec = CKM_API_ERROR_SOCKET;
            break;
        }

        if (0 == temp) {
            LogError("Read return 0/Connection closed by server(?)");
            ec = CKM_API_ERROR_SOCKET;
            break;
        }

        CKM::RawBuffer raw(buffer, buffer+temp);
        recv_buf.Push(raw);
    }
    while(!recv_buf.Ready());

    if(ec != CKM_API_SUCCESS)
        disconnect();

    return ec;
}

ServiceConnection::~ServiceConnection()
{
}

int try_catch(const std::function<int()>& func)
{
    int retval = CKM_API_ERROR_UNKNOWN;
    try {
        return func();
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("CKM::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return retval;
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

