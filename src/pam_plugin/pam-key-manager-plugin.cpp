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
 * @file        pam-key-manager-plugin.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       PAM module to handle session and password events.
 */

#include <sys/param.h>

#include <string>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <symbol-visibility.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <syslog.h>
#include <shadow.h>
#include <ckm/ckm-control.h>

namespace
{
#define PASSWORD_SHADOWED   "x"
std::string old_password;

bool identify_user_pwd(pam_handle_t *pamh, uid_t & uid, std::string & passwd)
{
    int pam_err;
    const char *user;
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return true;
    struct passwd *pwd;
    if ((pwd = getpwnam(user)) == NULL)
        return true;
    if(strcmp(pwd->pw_passwd, PASSWORD_SHADOWED)==0)
    {
        struct spwd *pwd_sh;
        if ((pwd_sh = getspnam(user)) == NULL)
            return true;
        passwd = std::string(pwd_sh->sp_pwdp);
    }
    else
        passwd = std::string(pwd->pw_passwd);
    uid = pwd->pw_uid;
    return false;
}
}

COMMON_API PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int /*flags*/, int /*argc*/, const char **/*argv*/)
{
    // identify user
    uid_t uid = -1;
    std::string passwd;
    if(identify_user_pwd(pamh, uid, passwd))
        return PAM_SESSION_ERR;

    auto control = CKM::Control::create();
    int ec = control->unlockUserKey(uid, passwd.c_str());
    if(ec == CKM_API_SUCCESS)
        return PAM_SUCCESS;

    if(ec == CKM_API_ERROR_AUTHENTICATION_FAILED)
    {
        pam_syslog(pamh, LOG_ERR, "key-manager and system password desynchronized,"
                                  "removing key-manager database for user: %d\n", uid);

        // key-manager<->system password desync
        // remove the user content
        ec = control->removeUserData(uid);
        if(ec == CKM_API_SUCCESS) {
            ec = CKM::Control::create()->unlockUserKey(uid, passwd.c_str());
            if(ec == CKM_API_SUCCESS)
                return PAM_SUCCESS;
            pam_syslog(pamh, LOG_ERR, "key-manager and system password desynchronized,"
                                      "attempt to create new database failed: %d\n", ec);
        } else {
            pam_syslog(pamh, LOG_ERR, "key-manager and system password desynchronized and"
                                      "recovery attempt to remove broken database failed: %d\n", ec);
        }
    }

    return PAM_SESSION_ERR;
}

COMMON_API PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int /*flags*/, int /*argc*/, const char **/*argv*/)
{
    // identify user
    uid_t uid = -1;
    std::string passwd;
    if(identify_user_pwd(pamh, uid, passwd))
        return PAM_SESSION_ERR;

    if(CKM::Control::create()->lockUserKey(uid) == CKM_API_SUCCESS)
        return PAM_SUCCESS;

    return PAM_SESSION_ERR;
}

COMMON_API PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if(argc==0) {
        pam_syslog(pamh, LOG_ERR, "key-manager plugin called with inappropriate arguments\n");
        return PAM_SERVICE_ERR;
    }

    // identify user
    uid_t uid = -1;
    std::string passwd;
    if(identify_user_pwd(pamh, uid, passwd))
        return PAM_USER_UNKNOWN;

    // attention: argv[0] is the argument, not the binary/so name
    // args are in arg_name=value format
    if(strstr(argv[0], "change_step"))
    {
        if(strstr(argv[0], "before"))
        {
            if( ! (flags & PAM_PRELIM_CHECK))
                old_password = passwd;
            return PAM_SUCCESS;
        }
        else if(strstr(argv[0], "after"))
        {
            if(flags & PAM_PRELIM_CHECK)
                return PAM_SUCCESS;

            if(old_password.size() == 0) {
                pam_syslog(pamh, LOG_ERR, "attempt to change key-manager password w/o old password\n");
                return PAM_SERVICE_ERR;
            }
            std::string local_old_pwd = old_password;
            old_password.clear();

            // CKM does not allow to change user password if database does
            // not exists. We must create database before change password.
            auto ctrl = CKM::Control::create();
            int ec = ctrl->unlockUserKey(uid, local_old_pwd.c_str());
            if (CKM_API_SUCCESS != ec) {
                // no DB reset here: somebody else might have changed password in mean time
                // if desync happened, next login attempt will remove the DB
                pam_syslog(pamh, LOG_ERR, "attempt to change key-manager password failed:"
                                          "can not open/create the database, ec: %d\n", ec);
                return PAM_SERVICE_ERR;
            }

            ec = ctrl->changeUserPassword(uid, local_old_pwd.c_str(), passwd.c_str());
            if (CKM_API_SUCCESS != ec) {
                pam_syslog(pamh, LOG_ERR, "attempt to change key-manager password ec: %d\n", ec);
                return PAM_SERVICE_ERR;
            }

            return PAM_SUCCESS;
        }
    }

    pam_syslog(pamh, LOG_ERR, "key-manager plugin called with no valid \"change_step\" option setting\n");
    return PAM_SERVICE_ERR;
}
