/*
 *  ckm-manager
 *
 *  Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      ://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/smack.h>
#include <unistd.h>
#include <fts.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <limits>

#include <key-manager-util.h>
#include <dpl/log/log.h>



namespace {
const size_t SIZE_T_MAX = std::numeric_limits<size_t>::max();
} // namespace anonymous

namespace CKM {

int util_smack_label_is_valid(const char *smack_label)
{
    int i;

    if (!smack_label || smack_label[0] == '\0' || smack_label[0] == '-')
        goto err;

    for (i = 0; smack_label[i]; ++i) {
        if (i >= SMACK_LABEL_LEN)
            return 0;
        switch (smack_label[i]) {
            case '~':
            case ' ':
            case '/':
            case '"':
            case '\\':
            case '\'':
                goto err;
            default:
                break;
        }
    }

    return 1;
err:
    LogError("Invalid Smack label: " << (smack_label ? smack_label : ""));
    return 0;
}

char *read_exe_path_from_proc(pid_t pid)
{
    char link[32];
    char *exe = NULL;
    size_t size = 64;
    ssize_t cnt = 0;

    // get link to executable
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);

    for (;;)
    {
        exe = (char*) malloc(size);
        if (exe == NULL)
        {
            LogError("Out of memory");
            return NULL;
        }

        // read link target
        cnt = readlink(link, exe, size);

        // error
        if (cnt < 0 || (size_t) cnt > size)
        {
            LogError("Can't locate process binary for pid=" << pid);
            free(exe);
            return NULL;
        }

        // read less than requested
        if ((size_t) cnt < size)
            break;

        // read exactly the number of bytes requested
        free(exe);
        if (size > (SIZE_T_MAX >> 1))
        {
            LogError("Exe path too long (more than " << size << " characters)");
            return NULL;
        }
        size <<= 1;
    }
    // readlink does not append null byte to buffer.
    exe[cnt] = '\0';
    return exe;
}

void rawBufferToX509(X509 **ppCert, SafeBuffer rawCert) {
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_write(bio, rawCert.data(), rawCert.size());
  d2i_X509_bio(bio, ppCert);
  BIO_free_all(bio);
}

void x509ToSafeBuffer(SafeBuffer &buf, X509 *cert) {
  int len = i2d_X509(cert, NULL);
  unsigned char tmpBuff[len];
  unsigned char *p = tmpBuff;
  i2d_X509(cert, &p);
  buf.assign(tmpBuff, tmpBuff +len);
}

STACK_OF(X509) *loadSystemCerts( const char * dirpath) {
    FTS *fts = NULL;
    FTSENT *ftsent;
    char tmp[10];
    STACK_OF(X509) *systemCerts = sk_X509_new_null();
    const char *dir_path[2];
    X509 *cert;

    dir_path[0] = dirpath;
    dir_path[1] = NULL;

    if (NULL == (fts = fts_open((char * const *) dir_path, FTS_LOGICAL, NULL))) {
        printf("Fail to open directories. dir=%s \n", dirpath);
        return NULL;
    }

    while ((ftsent = fts_read(fts)) != NULL) {
        if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
                printf("Fail to read directories. dir=%s \n", dirpath);
                fts_close(fts);
                return NULL;
        }

        if (ftsent->fts_info != FTS_F)
            continue;

        if (-1 != readlink(ftsent->fts_path, tmp, 10)) // ignore link file
            continue;

        cert = loadCert(ftsent->fts_path);
        if(cert != NULL) {
                sk_X509_push(systemCerts, cert);
        }
    }
    if (fts != NULL)
        fts_close(fts);

    return systemCerts;
}


X509 *loadCert(const char *file) {
    FILE *fp = fopen(file, "r");
    if(fp == NULL)
        return NULL;
    X509 *cert;
    if(!(cert = d2i_X509_fp(fp, NULL))) {
        fseek(fp, 0, SEEK_SET);
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
    }
    fclose(fp);
    return cert;
}


} // namespace CKM

