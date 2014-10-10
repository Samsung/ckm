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
 * @file       connection-thread.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <connection-thread.h>
#include <unistd.h>
#include <poll.h>
#include <dpl/log/log.h>
#include <client-common.h>

namespace CKM {

namespace {
const int POLL_TIMEOUT = 8000;
} // namespace anonymous

ConnectionThread::Pipe::Pipe()
{
    if (-1 == pipe(m_pipe))
        ThrowMsg(PipeError, "Pipe creation failed " << strerror(errno));
}

ConnectionThread::Pipe::~Pipe()
{
    close(m_pipe[0]);
    close(m_pipe[1]);
}

void ConnectionThread::Pipe::notify()
{
    if (-1 == TEMP_FAILURE_RETRY(write(m_pipe[1],"j",1)))
        ThrowMsg(PipeError, "Writing pipe failed " << strerror(errno));
}

ConnectionThread::ConnectionThread() :
    m_join(false),
    m_finished(false)
{
}

ConnectionThread::~ConnectionThread() {
    m_join = true;
    m_pipe.notify();
    m_thread.join();
}

void ConnectionThread::run() {
    m_thread = std::thread(&ConnectionThread::threadLoop, this);
}

void ConnectionThread::sendMessage(AsyncRequest&& req) {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_waitingReqs.push(std::move(req));
    lock.unlock();

    // notify via pipe
    m_pipe.notify();
}

void ConnectionThread::threadLoop()
{
    try {
        m_descriptors.add(m_pipe.output(),
                          POLLIN,
                          [this](int fd, short revents){ newRequest(fd, revents); });

        while (!m_join) {
            // wait for pipe/socket notification
            m_descriptors.wait();
        }
    } catch (CKM::Exception &e) {
        LogError("CKM::Exception::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }

    // cleanup services
    for(auto& it: m_services)
        it.second.serviceError(CKM_API_ERROR_UNKNOWN);
    m_services.clear();

    // close all descriptors (including pipe)
    m_descriptors.purge();

    // remove waiting requests and notify about error
    std::unique_lock<std::mutex> lock(m_mutex);
    while(!m_waitingReqs.empty()) {
        m_waitingReqs.front().observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
        m_waitingReqs.pop();
    }
    lock.unlock();

    m_finished = true;
}

void ConnectionThread::readPipe(int pipe, short revents)
{
    char buffer[1];

    if ((revents & POLLIN) == 0)
        ThrowMsg(PipeError, "Unexpected event: " << revents << "!=" << POLLIN);

    if(1 != TEMP_FAILURE_RETRY(read(pipe,buffer, 1))) {
        int err = errno;
        ThrowMsg(PipeError, "Failed to read pipe: " << strerror(err));
    }
}

Service& ConnectionThread::getService(const std::string& interface)
{
    auto it = m_services.find(interface);
    if (it != m_services.end())
        return it->second;

    // create new service, insert it and return
    return m_services.insert(
            std::make_pair(interface,Service(m_descriptors, interface))).first->second;
}

void ConnectionThread::newRequest(int pipe, short revents)
{
    readPipe(pipe, revents);

    std::unique_lock<std::mutex> lock(m_mutex);

    // nothing to do?
    if(m_waitingReqs.empty()) {
        LogWarning("Empty request queue. Are we exiting?");
        return;
    }

    // zero-copy remove
    AsyncRequest req = std::move(m_waitingReqs.front());
    m_waitingReqs.pop();

    lock.unlock();

    Service& srv = getService(req.interface);
    srv.addRequest(std::move(req));
}

} /* namespace CKM */
