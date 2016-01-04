/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 *
 * @file        glib-logic.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Dbus listener implementation as service.
 */
#pragma once

#include <glib.h>

#include <noncopyable.h>
#include <package_manager.h>
#include <service-messages.h>

namespace CKM {

class GLIBLogic {
public:
    GLIBLogic();
    
    NONCOPYABLE(GLIBLogic);

    void LoopStart();
    void LoopStop();
    void SetCommManager(CommMgr *manager);
    virtual ~GLIBLogic();
protected:
    static void packageEventCallbackStatic(
        uid_t uid,
        const char *type,
        const char *package,
        package_manager_event_type_e eventType,
        package_manager_event_state_e eventState,
        int progress,
        package_manager_error_e error,
        void *userData);

    void packageEventCallback(
        uid_t uid,
        const char *type,
        const char *package,
        package_manager_event_type_e eventType,
        package_manager_event_state_e eventState,
        int progress,
        package_manager_error_e error);

    CommMgr *m_commMgr;
    GMainLoop *m_gMainLoop;
};

} // namespace CKM

