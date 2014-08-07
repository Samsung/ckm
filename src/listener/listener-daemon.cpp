#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <package_manager.h>
#include <ckm/ckm-control.h>
#include <dlog.h>

#define CKM_TAG "CKM_LISTENER"

void eventCallback(
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

    if (eventType != PACKAGE_MANAGER_EVENT_TYPE_UNINSTALL)
        return;

    if (eventState != PACKAGE_MANAGER_EVENT_STATE_STARTED)
        return;

    if (package == NULL)
        return;

    SLOG(LOG_DEBUG, CKM_TAG, "Get callback. Uninstalation of: %s", package);
    auto control = CKM::Control::create();
    control->removeApplicationData(std::string(package));
}

int main(void) {
    SLOG(LOG_DEBUG, CKM_TAG, "%s", "Start!");

    // Let's operate in background
    int result = fork();
    if (result < 0){
        SLOG(LOG_DEBUG, CKM_TAG, "%s", "Error in fork!");
        exit(1);
    }

    if (result > 0)
        exit(0);

    // Let's disconnect from terminal
    if (-1 == setsid()) {
        SLOG(LOG_DEBUG, CKM_TAG, "%s", "Error in fork!");
        exit(1);
    }

    // Let's close all descriptors
//    for (result = getdtablesize(); result>=0; --result)
//        close(result);

//    result = open("/dev/null", O_RDWR); // open stdin
//    dup(result); // stdout
//    dup(result); // stderr

    umask(027);

    // Let's change current directory
    if (-1 == chdir("/")) {
        SLOG(LOG_DEBUG, CKM_TAG, "%s", "Error in chdir!");
        exit(1);
    }

    // Let's create lock file
    result = open("/tmp/ckm-listener.lock", O_RDWR | O_CREAT, 0640);
    if (result < 0) {
        SLOG(LOG_DEBUG, CKM_TAG, "%s", "Error in opening lock file!");
        exit(1);
    }

    if (lockf(result, F_TLOCK, 0) < 0) {
        SLOG(LOG_DEBUG, CKM_TAG, "%s", "Daemon already working!");
        exit(0);
    }

    char str[100];
    sprintf(str, "%d\n", getpid());
    result = write(result, str, strlen(str));

    SLOG(LOG_DEBUG, CKM_TAG, "%s", str);

    // Let's start to listen
    GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);
    package_manager_h request;

    package_manager_create(&request);
    if (0 != package_manager_set_event_cb(request, eventCallback, NULL)) {
        SLOG(LOG_DEBUG, CKM_TAG, "%s", "Error in package_manager_set_event_cb");
        exit(-1);
    }

    /* Change file mode mask */

    SLOG(LOG_DEBUG, CKM_TAG, "%s", "Ready to listen!");
    g_main_loop_run(main_loop);
    return 0;
}

