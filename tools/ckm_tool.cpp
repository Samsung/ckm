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
 * @file       ckm_tool.cpp
 * @author     Maciej J. Karpiuk (m.karpiuk2@samsung.com)
 * @version    1.0
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <errno.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-control.h>

using namespace std;

bool parseLong(const char *buf_ptr, long int &val)
{
    char *temp;
    errno = 0;
    long int val_tmp = strtol(buf_ptr, &temp, 0);
    if(errno)
        return true;
    val = val_tmp;
    return false;
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        cerr << "Usage: ckm_tool [option] [opt_arg]" << endl;
        cerr << "option: " << endl;
        cerr << "\t-d\tdelete user database, opt_arg specified the user UID" << endl;
        cerr << "Example: ckm_tool -l 5000" << endl;
        return -1;
    }

    // simple input arg parser
    for (int i=1; i<argc-1; i++)
    {
        long int uid;
        if(!strcmp(argv[i], "-d"))
        {
            if(parseLong(argv[i+1], uid) || uid<0) {
                cerr << "parameter error: invalid UID provided to the -d option" << endl;
                exit(-2);
            }

            // lock the database
            auto control = CKM::Control::create();
            int ec = control->lockUserKey(static_cast<uid_t>(uid));
            if(ec != CKM_API_SUCCESS) {
                cerr << "Failed, lock DB error: " << ec << endl;
                exit(ec);
            }

            // remove the user content
            ec = control->removeUserData(static_cast<uid_t>(uid));
            if(ec != CKM_API_SUCCESS) {
                cerr << "Failed, remove user data error: " << ec << endl;
                exit(ec);
            }
        }
        else {
            std::cout << "Not enough or invalid arguments, please try again.\n";
            exit(-1);
        }
    }

    return 0;
}
