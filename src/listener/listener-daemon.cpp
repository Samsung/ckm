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
 * @file        listener-daemon.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Listener daemon handle some events for key-manager.
 */

#include <fcntl.h>
#include <unistd.h>

#include <glib.h>
#include <package_manager.h>
#include <ckm/ckm-control.h>
#include <ckm/ckm-type.h>
#include <dlog.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CKM_LISTENER"

namespace {
const char* const CKM_LOCK = RUN_DIR "/" SERVICE_NAME "/key-manager.pid";
};

bool isCkmRunning()
{
    int lock = TEMP_FAILURE_RETRY(open(CKM_LOCK, O_RDWR));
    if (lock == -1)
        return false;

    int ret = lockf(lock, F_TEST, 0);
    close(lock);

    // if lock test fails because of an error assume ckm is running
    return (0 != ret);
}

void packageUninstalledEventCallback(
    const char *type,
    const char *package,
    package_manager_event_type_e eventType,
    package_manager_event_state_e eventState,
    int progress,
    package_manager_error_e error,
    void *userData)
{
    (void) type;
    (void) progress;
    (void) error;
    (void) userData;

    if (eventType != PACKAGE_MANAGER_EVENT_TYPE_UNINSTALL ||
            eventState != PACKAGE_MANAGER_EVENT_STATE_STARTED ||
            package == NULL)
        return;

    SLOGD("PackageUninstalled Callback. Uninstalation of: %s", package);

    if (!isCkmRunning()) {
        SLOGE("package uninstall event recieved but ckm isn't running!");
        return;
    }

    auto control = CKM::Control::create();
    int ret = control->removeApplicationData(std::string(package));
    if (ret != CKM_API_SUCCESS)
        SLOGE("CKM::Control::removeApplicationData error. ret : %d", ret);
    else
        SLOGD("CKM::Control::removeApplicationData success. Uninstallation package : %s", package);
}

int main(void)
{
    SLOGD("Start!");

    GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);

    package_manager_h request;
    package_manager_create(&request);

    SLOGD("register uninstalledApp event callback start");
    if (0 != package_manager_set_event_cb(request, packageUninstalledEventCallback, NULL)) {
        SLOGE("Error in package_manager_set_event_cb");
        exit(-1);
    }
    SLOGD("Ready to listen!");
    g_main_loop_run(main_loop);

    return 0;
}

