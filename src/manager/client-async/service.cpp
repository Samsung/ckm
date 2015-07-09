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
 * @file       service.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <service.h>

#include <dpl/errno_string.h>
#include <dpl/log/log.h>

#include <storage-receiver.h>
#include <ocsp-receiver.h>
#include <encryption-receiver.h>
#include <protocols.h>

namespace CKM {

namespace {
const size_t RECV_BUFFER_SIZE = 2048;
}

Service::Service(IDescriptorSet& descriptors, const std::string& interface) :
    m_interface(interface),
    m_descriptors(descriptors)
{
}

void Service::addRequest(AsyncRequest&& req)
{
    if(!m_socket) {
        m_socket.reset(new SockRAII());
        int ret;
        if (CKM_API_SUCCESS != (ret = m_socket->connect(m_interface.c_str()))) {
            LogError("Socket connection failed: " << ret);
            m_socket.reset();
            req.observer->ReceivedError(ret);
            return;
        }
    }

    if (m_sendQueue.empty())
        watch(POLLOUT);

    m_sendQueue.push(std::move(req));
}

void Service::serviceError(int error)
{
    if (m_socket)
    {
        // stop listening on socket
        m_descriptors.remove(m_socket->get(), false);
        // close the socket
        m_socket.reset();
    }

    // notify observers waiting for response
    for(const auto& it: m_responseMap) {
        it.second.observer->ReceivedError(error);
    }
    m_responseMap.clear();

    // notify observers waiting for send
    while(!m_sendQueue.empty()) {
        m_sendQueue.front().observer->ReceivedError(error);
        m_sendQueue.pop();
    }

    // clear response buffer
    m_responseBuffer.reset();
}

void Service::socketReady(int sock, short revents)
{
    if (sock != m_socket->get()) {
        LogError("Unexpected socket: " << sock << "!=" << m_socket->get());
        serviceError(CKM_API_ERROR_SOCKET);
        return;
    }

    try {
        if (revents & POLLOUT)
            sendData();
        else if (revents & POLLIN)
            receiveData();
        else {
            LogError("Unexpected event: " << revents << "!=" << POLLOUT);
            serviceError(CKM_API_ERROR_SOCKET);
        }
    } catch (const IReceiver::BadResponse&) {
        serviceError(CKM_API_ERROR_BAD_RESPONSE);
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
        serviceError(CKM_API_ERROR_UNKNOWN);
    } catch (...) {
        LogError("Unknown exception occurred");
        serviceError(CKM_API_ERROR_UNKNOWN);
    }
}

void Service::sendData()
{
    // nothing to send? -> stop watching POLLOUT
    if (m_sendQueue.empty()) {
        watch(POLLIN);
        return;
    }

    while (!m_sendQueue.empty()) {
        AsyncRequest& req = m_sendQueue.front();

        ssize_t temp = TEMP_FAILURE_RETRY(write(m_socket->get(),
                                                &req.buffer[req.written],
                                                req.buffer.size() - req.written));
        if (-1 == temp) {
            int err = errno;
            // can't write? -> go to sleep
            if (EAGAIN == err || EWOULDBLOCK == err)
                return;

            LogError("Error in write: " << GetErrnoString(err));
            serviceError(CKM_API_ERROR_SEND_FAILED);
            return;
        }

        req.written += temp;

        // finished? -> move request to response map
        if(req.written == req.buffer.size()) {
            AsyncRequest finished = std::move(m_sendQueue.front());
            m_sendQueue.pop();

            // update poll flags if necessary
            if(m_sendQueue.empty() || m_responseMap.empty())
                watch((m_sendQueue.empty()? 0 : POLLOUT) | POLLIN);

            m_responseMap.insert(std::make_pair(finished.id,finished));
        }
    }
}

void Service::receiveData()
{
    char buffer[RECV_BUFFER_SIZE];

    ssize_t temp = TEMP_FAILURE_RETRY(read(m_socket->get(), buffer, RECV_BUFFER_SIZE));
    if (-1 == temp) {
        int err = errno;
        LogError("Error in read: " << GetErrnoString(err));
        serviceError(CKM_API_ERROR_RECV_FAILED);
        return;
    }

    if (0 == temp) {
        LogError("Read return 0/Connection closed by server(?)");
        serviceError(CKM_API_ERROR_RECV_FAILED);
        return;
    }

    if (!m_responseBuffer)
        m_responseBuffer.reset(new MessageBuffer());

    RawBuffer raw(buffer, buffer+temp);
    m_responseBuffer->Push(raw);

    // parse while you can
    while(m_responseBuffer->Ready())
    {
        std::unique_ptr<IReceiver> receiver;
        if (m_interface == SERVICE_SOCKET_CKM_STORAGE)
            receiver.reset(new StorageReceiver(*m_responseBuffer, m_responseMap));
        else if (m_interface == SERVICE_SOCKET_OCSP)
            receiver.reset(new OcspReceiver(*m_responseBuffer, m_responseMap));
        else if (m_interface == SERVICE_SOCKET_ENCRYPTION)
            receiver.reset(new EncryptionReceiver(*m_responseBuffer, m_responseMap));
        else {
            LogError("Unknown service " << m_interface);
            serviceError(CKM_API_ERROR_RECV_FAILED);
            return;
        }
        receiver->processResponse();

        if (m_responseMap.empty())
            watch(m_sendQueue.empty()?0:POLLOUT);
    }
}

void Service::watch(short events)
{
    if (0 == events)
        m_descriptors.remove(m_socket->get(), false);
    else
        m_descriptors.add(m_socket->get(),
                          events,
                          [this](int sock, short revents){ socketReady(sock, revents); });
}

} // namespace CKM
