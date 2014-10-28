/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        generic-socket-manager.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of GenericSocketService and GenericSocketManager.
 */

#ifndef _CENT_KEY_MNG_GENERIC_SERVICE_MANAGER_
#define _CENT_KEY_MNG_GENERIC_SERVICE_MANAGER_

#include <vector>
#include <string>

#include <sys/types.h>

#include <dpl/exception.h>
#include <protocols.h>
#include <generic-event.h>
#include <dpl/raw-buffer.h>

extern "C" {
struct msghdr;
} // extern "C"

namespace CKM {

typedef int InterfaceID;

struct Credentials {
    uid_t uid;
    Label smackLabel;
};

struct ConnectionID {
    int sock;                                 // This is decriptor used for connection
    int counter;                              // Unique handler per socket
    inline bool operator<(const ConnectionID &second) const {
        return counter < second.counter;
    }
};

struct GenericSocketManager;

struct GenericSocketService {
    typedef std::string ServiceHandlerPath;
    struct ServiceDescription {
        ServiceDescription(const char *path,
            const char *smackLabel,
            InterfaceID interfaceID = 0,
            bool useSendMsg = false)
          : smackLabel(smackLabel)
          , interfaceID(interfaceID)
          , serviceHandlerPath(path)
          , useSendMsg(useSendMsg)
        {}

        Label smackLabel;                      // Smack label for socket
        InterfaceID interfaceID;               // All data from serviceHandlerPath will be marked with this interfaceHandler
        ServiceHandlerPath serviceHandlerPath; // Path to file
        bool useSendMsg;
    };

    typedef std::vector<ServiceDescription> ServiceDescriptionVector;

    struct AcceptEvent : public GenericEvent {
        ConnectionID connectionID;
        InterfaceID interfaceID;
        Credentials credentials;
    };

    struct WriteEvent : public GenericEvent {
        ConnectionID connectionID;
        size_t size;
        size_t left;
    };

    struct ReadEvent : public GenericEvent {
        ConnectionID connectionID;
        RawBuffer rawBuffer;
    };

    struct CloseEvent : public GenericEvent {
        ConnectionID connectionID;
    };

    virtual void SetSocketManager(GenericSocketManager *manager) {
        m_serviceManager = manager;
    }

    virtual ServiceDescriptionVector GetServiceDescription() = 0;
    virtual void Event(const AcceptEvent &event) = 0;
    virtual void Event(const WriteEvent &event) = 0;
    virtual void Event(const ReadEvent &event) = 0;
    virtual void Event(const CloseEvent &event) = 0;

    GenericSocketService() : m_serviceManager(NULL) {}
    virtual ~GenericSocketService(){}
protected:
    GenericSocketManager *m_serviceManager;
};

struct GenericSocketManager {
    virtual void MainLoop() = 0;
    virtual void RegisterSocketService(GenericSocketService *ptr) = 0;
    virtual void Close(ConnectionID connectionID) = 0;
    virtual void Write(ConnectionID connectionID, const RawBuffer &rawBuffer) = 0;
    virtual ~GenericSocketManager(){}
};

} // namespace CKM

#endif // _CENT_KEY_MNG_GENERIC_SERVICE_MANAGER_
