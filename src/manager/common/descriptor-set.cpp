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
 * @file       descriptor-set.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include "descriptor-set.h"
#include <dpl/log/log.h>
#include <string.h>
#include <unistd.h>

namespace CKM {

DescriptorSet::DescriptorSet() : m_dirty(true), m_fds(NULL) {
}

DescriptorSet::~DescriptorSet() {
    purge();
}

void DescriptorSet::purge() {
    for(auto it:m_descriptors)
        close(it.first);
    m_descriptors.clear();
}

void DescriptorSet::add(int fd, short events, Callback&& callback) {
    // map operator[] requires empty DescriptorData constructor
    auto it = m_descriptors.find(fd);
    if (it == m_descriptors.end()) {
        m_descriptors.insert(std::make_pair(fd,DescriptorData(events, std::move(callback))));
    } else {
        it->second.events = events;
        it->second.callback = std::move(callback);
    }
    m_dirty = true;
}

void DescriptorSet::remove(int fd, bool close_fd) {
    if (0 != m_descriptors.erase(fd)) {
        if (close_fd)
            close(fd);
        m_dirty = true;
    }
}

void DescriptorSet::wait(int timeout_ms) {
    if(!rebuildPollfd())
        return;

    // wait
    int ret = TEMP_FAILURE_RETRY(poll(m_fds, m_descriptors.size(), timeout_ms));
    if (ret == 0) {
        ThrowMsg(Timeout, "Poll timeout");
    } else if (ret < 0) {
        int err = errno;
        ThrowMsg(InternalError, "Poll failed " << strerror(err));
    }

    notify(ret);
}

bool DescriptorSet::rebuildPollfd() {
    if (m_dirty) {
       delete[] m_fds;
       m_fds = NULL;
       if (m_descriptors.empty()) {
           LogWarning("Nothing to wait for");
           return false;
       }

       m_fds = new pollfd[m_descriptors.size()];
       size_t idx = 0;
       for(const auto& it : m_descriptors) {
           m_fds[idx].fd = it.first;
           m_fds[idx].events = it.second.events;
           idx++;
       }
       m_dirty = false;
    }
    return true;
}

void DescriptorSet::notify(int descCount) {
    size_t size = m_descriptors.size();
    for(size_t idx = 0;idx < size;++idx) {
        const pollfd& pfd = m_fds[idx];
        if (pfd.revents == 0)
            continue;

        /*
         * Descriptors can be added/removed inside observer callback but:
         * 1. m_fds is not affected. It will be regenerated in next wait()
         * 2. No m_descriptors iterator will be invalidated
         * 3. m_descriptors size is stored in local variable
         */
        m_descriptors.at(pfd.fd).callback(pfd.fd, pfd.revents);
        descCount--;

        // no more descriptors to check
        if (descCount == 0)
            break;
    }
    if (descCount != 0)
        ThrowMsg(InternalError, "Number of notified descriptors do not match");
}

} /* namespace CKM */
