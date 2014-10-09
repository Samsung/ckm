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

#include <vector>
#include <functional>

#include <noncopyable.h>
#include <ckm/ckm-type.h>
#include <message-buffer.h>
#include <protocols.h>

#define KEY_MANAGER_API __attribute__((visibility("default")))

extern "C" {
    struct msghdr;
}

namespace CKM {

class AliasSupport
{
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

        int Connect(char const * const interface);
        void Disconnect();
        bool isConnected() const;
        int Get() const;

    protected:
        int WaitForSocket(int event, int timeout);

    private:
        int m_sock;
};

class ServiceConnection : public SockRAII
{
    public:
        ServiceConnection(char const * const service_interface);

        // roundtrip: send and receive
        int processRequest(const CKM::RawBuffer &send_buf,
                           CKM::MessageBuffer &recv_buf);

        // blocking
        int send(const CKM::RawBuffer &send_buf);
        int receive(CKM::MessageBuffer &recv_buf);

        virtual ~ServiceConnection();

    private:
        std::string m_service_interface;

        int Connect();
};


/*
 * Decorator function that performs frequently repeated exception handling in
 * SS client API functions. Accepts lambda expression as an argument.
 */
int try_catch(const std::function<int()>& func);

void try_catch_async(const std::function<void()>& func, const std::function<void(int)>& error);

} // namespace CKM

#endif // _KEY_MANAGER_CLIENT_
