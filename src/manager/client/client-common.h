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
 * @file        client-common.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of common types
 *              used in Central Key Manager.
 */

#ifndef _KEY_MANAGER_CLIENT_
#define _KEY_MANAGER_CLIENT_

#include <unistd.h>

#include <vector>
#include <functional>

#include <noncopyable.h>
#include <ckm/ckm-type.h>
#include <message-buffer.h>
#include <protocols.h>

extern "C" {
    struct msghdr;
}

namespace CKM {

class AliasSupport {
    public:
        AliasSupport(const Alias &alias);

        const Label & getLabel() const;
        const Name & getName() const;
        bool isLabelEmpty() const;

        static Alias merge(const Label &label, const Name &alias);

    private:
        Name m_name;
        Label m_label;
};

class SockRAII {
    public:
        SockRAII();

        NONCOPYABLE(SockRAII);

        virtual ~SockRAII();

        int connect(const char * interface);
        void disconnect();
        bool isConnected() const;
        int get() const;
        int waitForSocket(int event, int timeout);

    protected:
        int connectWrapper(int socket, const char *interface);
        int m_sock;
};

class ServiceConnection {
    public:
        ServiceConnection(const char * service_interface);

        // roundtrip: send and receive
        int processRequest(const CKM::RawBuffer &send_buf,
                           CKM::MessageBuffer &recv_buf);

        // blocking
        int send(const CKM::RawBuffer &send_buf);
        int receive(CKM::MessageBuffer &recv_buf);

        virtual ~ServiceConnection();

    protected:
        int prepareConnection();

        SockRAII m_socket;
        std::string m_serviceInterface;
};

/*
 * Decorator function that performs frequently repeated exception handling in
 * SS client API functions. Accepts lambda expression as an argument.
 */
int try_catch(const std::function<int()>& func);

void try_catch_async(const std::function<void()>& func, const std::function<void(int)>& error);

} // namespace CKM

#endif // _KEY_MANAGER_CLIENT_
