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
 * @file       descriptor-set.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <map>
#include <functional>
#include <dpl/exception.h>
#include <poll.h>
#include <noncopyable.h>

namespace CKM {

class IDescriptorSet {
public:
    // int is for descriptor, short is for revents,
    typedef std::function<void(int, short)> Callback;

    virtual void add(int fd, short events, Callback&& callback) = 0;
    virtual void remove(int fd, bool close_fd = true) = 0;
protected:
    // I don't want anyone to manage object lifetime via interface.
    IDescriptorSet() {}
    ~IDescriptorSet() {}
};

/**
 * @brief Wrapper for poll()
 */
class DescriptorSet : public IDescriptorSet {
public:
    DescriptorSet();
    virtual ~DescriptorSet();

    NONCOPYABLE(DescriptorSet);

    /*
     * Add descriptor fd to watched set. Watches for events. Takes ownership of fd (closes it). Will
     * synchronously call supported callback when an event occurs on descriptor. If descriptor
     * already exists in the set events and callback will be overwritten.
     *
     * @param fd       descriptor to be watched
     * @param events   events to watch for
     * @param callback callback to be called when an event on descriptor occurs
     */
    virtual void add(int fd, short events, Callback&& callback);
    /*
     * Removes give descriptor from watched set and closes it.
     *
     * @param fd       descriptor to be removed and closed
     */
    virtual void remove(int fd, bool close_fd = true);

    /*
     * Wait for descriptor events using poll().
     * Synchronously calls provided descriptor callbacks.
     *
     * @param timeout_ms  timeout in ms. egative value means no timeout.
     *
     * @throws Timeout exception in case of timeout
     * @throws InternalError in case of other error
     */
    void wait(int timeout_ms = 60000);
    /*
     * Removes and closes all descriptors
     */
    void purge();

    DECLARE_EXCEPTION_TYPE(CKM::Exception, InternalError);
    DECLARE_EXCEPTION_TYPE(CKM::Exception, Timeout);

protected:
    // returns false if there are no descriptors to wait for
    bool rebuildPollfd();
    void notify(int descCount);

    struct DescriptorData {
        DescriptorData(short e, Callback&& c) : events(e), callback(std::move(c)) {}

        short events;
        Callback callback;
    };

    std::map<int, DescriptorData> m_descriptors;

    // true if pollfd needs update
    bool m_dirty;
    pollfd* m_fds;
};

} /* namespace CKM */
