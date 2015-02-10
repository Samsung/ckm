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
 * @file       ckm_so_loader.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>

using namespace std;

enum {
    CLEAR_CACHE = 1,
    LAZY = 2
};

void clear_cache()
{
    sync();
    ofstream of("/proc/sys/vm/drop_caches");
    if (of.bad()) {
        cerr << "Cache clearing failed: " << strerror(errno) << endl;
        return;
    }
    of << "3";
}

void test(int flags, const string& library, const string& symbol)
{
    bool lazy = (flags & LAZY);
    if (flags & CLEAR_CACHE)
        clear_cache();

    chrono::time_point<chrono::high_resolution_clock> tp[4];

    tp[0] = chrono::high_resolution_clock::now();
    void* handle = dlopen(library.c_str(), (lazy?RTLD_LAZY:RTLD_NOW));
    tp[1] = chrono::high_resolution_clock::now();
    if (!handle) {
        cerr << "dlopen failed: " << dlerror() << endl;
        exit(1);
    }

    if (!symbol.empty())
    {
        tp[2] = chrono::high_resolution_clock::now();
        void* sym = dlsym(handle, symbol.c_str());
        tp[3] = chrono::high_resolution_clock::now();
        if (!sym) {
            cerr << "dlsym failed: " << dlerror() << endl;
            exit(1);
        }
    }
    dlclose(handle);

    cout << (tp[1] - tp[0]).count() << ";" << (tp[3] - tp[2]).count() << endl;
}

int main(int argc, char* argv[])
{
    if (argc < 5) {
        cerr << "Usage: ckm_so_loader [flags] [repeats] [library] [symbol]" << endl;
        cerr << " flags: 1-clear cache, 2-lazy binding" << endl;
        cerr << "Example: ckm_so_loader 3 100 /usr/lib/libkey-manager-client.so ckmc_save_key" << endl;
        return -1;
    }

    int flags = stoi(argv[1]); // let it throw
    int repeats = stoi(argv[2]); // let it throw
    string so_path(argv[3]);
    string symbol(argv[4]);

    cout << "dlopen[us];dlsym[us]" << endl;
    for (int cnt = 0 ; cnt < repeats; cnt++)
    {
        /*
         * It has to be a different process each time. Glibc somehow caches the library information
         * and consecutive calls are faster
         */
        pid_t pid = fork();
        if (pid < 0) {
            cerr << "fork failed: " << strerror(errno) << endl;
            return -1;
        }
        if (pid == 0) {
            test(flags, so_path, symbol);
            exit(0);
        }
        else
        {
            int status;
            pid_t ret = waitpid(pid,&status, 0);
            if (ret != pid) {
                cerr << "waitpid failed: " << strerror(errno) << endl;
                exit(1);
            }
        }
    }
    return 0;
}
