#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <systemd/sd-daemon.h>

#include <glib.h>
#include <package_manager.h>
#include <ckm/ckm-control.h>
#include <ckm/ckm-type.h>
#include <vconf/vconf.h>
#include <dlog.h>

#define CKM_LISTENER_TAG "CKM_LISTENER"

#ifndef VCONFKEY_SECURITY_MDPP_STATE
#define VCONFKEY_SECURITY_MDPP_STATE "file/security_mdpp/security_mdpp_state"
#endif

void daemonize()
{
    // Let's operate in background
    int result = fork();
    if (result < 0){
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "%s", "Error in fork!");
        exit(1);
    }

    if (result > 0)
        exit(0);

    // Let's disconnect from terminal
    if (-1 == setsid()) {
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "%s", "Error in fork!");
        exit(1);
    }

    // Let's close all descriptors
//    for (result = getdtablesize(); result>=0; --result)
//    close(result);

    close(0);
    close(1);
    close(2);

    result = open("/dev/null", O_RDWR); // open stdin

    int fd_stdout = 0;
    int fd_stderr = 0;
    fd_stdout = dup(result); // stdout
    fd_stderr = dup(result); // stderr
    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "%d : %s", fd_stdout, "stdout file descriptor");
    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "%d : %s", fd_stderr, "stderr file descriptor");


    umask(027);

    // Let's change current directory
    if (-1 == chdir("/")) {
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "%s", "Error in chdir!");
        exit(1);
    }

    // Let's create lock file
    result = open("/tmp/ckm-listener.lock", O_RDWR | O_CREAT, 0640);
    if (result < 0) {
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "%s", "Error in opening lock file!");
        exit(1);
    }

    if (lockf(result, F_TLOCK, 0) < 0) {
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "%s", "Daemon already working!");
        exit(0);
    }

    char str[100];
    sprintf(str, "%d\n", getpid());
    result = write(result, str, strlen(str));

    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "%s", str);
}

void callUpdateCCMode()
{
    // TODO make it call ckm only if it's already running (lock file)
    auto control = CKM::Control::create();
    int ret = control->updateCCMode();

    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "Callback caller process id : %d\n", getpid());

    if ( ret != CKM_API_SUCCESS )
        SLOG(LOG_ERROR, CKM_LISTENER_TAG, "CKM::Control::updateCCMode error. ret : %d\n", ret);
    else
        SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "CKM::Control::updateCCMode success.\n");
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

void ccModeChangedEventCallback(keynode_t*, void*)
{
    callUpdateCCMode();
}

int main(void) {
    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "%s", "Start!");

    daemonize();

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

    SLOG(LOG_DEBUG, CKM_LISTENER_TAG, "%s", "Ready to listen!");
    g_main_loop_run(main_loop);
    return 0;
}

