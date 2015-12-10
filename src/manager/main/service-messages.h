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
 * @file       service-messages.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <memory>

#include <credentials.h>
#include <ckm/ckm-type.h>
#include <protocols.h>
#include <ckm/ckm-error.h>
#include <communication-manager.h>
#include <generic-backend/gobj.h>

namespace CKM {

// inter-service communication message base class
struct MsgBase {
    explicit MsgBase(int id) : id(id) {}
    virtual ~MsgBase() {}

    int id;
};

// key request
struct MsgKeyRequest : public MsgBase {
    MsgKeyRequest(int id,
                  const Credentials& cred,
                  const Name& name,
                  const Label& label,
                  const Password& password) :
        MsgBase(id),
        cred(cred),
        name(name),
        label(label),
        password(password)
    {
    }

    Credentials cred;
    Name name;
    Label label;
    Password password;
};

// key response
struct MsgKeyResponse : public MsgBase {
    MsgKeyResponse(int id, const Crypto::GObjShPtr& key, int errorCode = CKM_API_SUCCESS) :
        MsgBase(id),
        key(key),
        error(errorCode)
    {
    }

    Crypto::GObjShPtr key;
    int error;
};

typedef CommunicationManager<MsgKeyRequest, MsgKeyResponse> CommMgr;

} /* namespace CKM */
