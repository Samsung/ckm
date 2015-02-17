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

#ifdef SECURITY_MDFPP_STATE_ENABLE
#include <vconf/vconf.h>
#endif

#define CKM_LISTENER_TAG "CKM_LISTENER"

#if defined(SECURITY_MDFPP_STATE_ENABLE) && !defined(VCONFKEY_SECURITY_MDPP_STATE)
#define VCONFKEY_SECURITY_MDPP_STATE "file/security_mdpp/security_mdpp_state"
#endif

namespace {
const char* const CKM_LOCK = "/var/run/key-manager.pid";
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

#ifdef SECURITY_MDFPP_STATE_ENABLE
void callUpdateCCMode()
{
    if(!isCkmRunning())
        return;

    auto control = CKM::Control::create();
    int ret = control->updateCCMode();

    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "Callback caller process id : %d\n", getpid());

    if ( ret != CKM_API_SUCCESS )
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "CKM::Control::updateCCMode error. ret : %d\n", ret);
    else
        SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "CKM::Control::updateCCMode success.\n");
}

void ccModeChangedEventCallback(keynode_t*, void*)
{
    callUpdateCCMode();
}
#endif


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
            package == NULL) {
        SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "PackageUninstalled Callback error of Invalid Param");
    }
    else {
        SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "PackageUninstalled Callback. Uninstalation of: %s", package);
        auto control = CKM::Control::create();
        int ret = 0;
        if ( CKM_API_SUCCESS != (ret = control->removeApplicationData(std::string(package))) ) {
            SLOG(LOG_ERROR, CKM_LISTENER_TAG, "CKM::Control::removeApplicationData error. ret : %d\n", ret);
        }
        else {
            SLOG(LOG_DEBUG, CKM_LISTENER_TAG,
                "CKM::Control::removeApplicationData success. Uninstallation package : %s\n", package);
        }
    }
}

int main(void) {
    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "%s", "Start!");

    // Let's start to listen
    GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);

    package_manager_h request;
    package_manager_create(&request);

    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "register uninstalledApp event callback start");
    if (0 != package_manager_set_event_cb(request, packageUninstalledEventCallback, NULL)) {
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "%s", "Error in package_manager_set_event_cb");
        exit(-1);
    }
    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "register uninstalledApp event callback success");

#ifdef SECURITY_MDFPP_STATE_ENABLE
    int ret = 0;
    char *mdpp_state = vconf_get_str(VCONFKEY_SECURITY_MDPP_STATE);
    if ( mdpp_state ) { // Update cc mode and register event callback only when mdpp vconf key exists
        callUpdateCCMode();

        SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "register vconfCCModeChanged event callback start");
        if ( 0 != (ret = vconf_notify_key_changed(VCONFKEY_SECURITY_MDPP_STATE, ccModeChangedEventCallback, NULL)) ) {
            SLOG(LOG_ERROR, CKM_LISTENER_TAG, "Error in vconf_notify_key_changed. ret : %d", ret);
            exit(-1);
        }
        SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "register vconfCCModeChanged event callback success");
    }
    else
        SLOG(LOG_DEBUG, CKM_LISTENER_TAG,
            "vconfCCModeChanged event callback is not registered. No vconf key exists : %s", VCONFKEY_SECURITY_MDPP_STATE);
#endif

    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "%s", "Ready to listen!");
    g_main_loop_run(main_loop);
    return 0;
}

