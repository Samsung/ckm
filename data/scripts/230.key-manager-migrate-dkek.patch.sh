#!/bin/bash

CKM_DATA_PATH=/opt/data/ckm
VERSION_INFO_PATH=${CKM_DATA_PATH}/version-info
CURRENT_VERSION=1

migrate_from_0_to_1()
{
    ARR_UID=()
    ARR_IDX=()

    # Extract uids from DKEK files
    for uid in `ls ${CKM_DATA_PATH} | grep "^key-[0-9]*-[0-9]*$" | awk 'BEGIN { FS = "-" }; { print $2 }' | awk '!x[$0]++'`
    do
        ARR_UID+=($uid)
    done

    for (( i = 0; i < ${#ARR_UID[@]}; i++ ))
    do
        idx_max=0
        idx_submax=0

        uid=${ARR_UID[$i]}
        ARR_IDX=()
        # Extract autoincremented index per uids
        for file in `ls ${CKM_DATA_PATH} | grep "^key-${uid}-[0-9]*$"`
        do
            idx=`echo $file | awk 'BEGIN { FS = "-" }; { print $3 }'`
            ARR_IDX+=($idx)
        done

        # Find max index(for key-<uid>) and submax index(for key-backup-<uid>)
        for idx in ${ARR_IDX[@]}
        do
            if [ $idx -gt $idx_max ]
            then
                idx_submax=$idx_max
                idx_max=$idx
            fi
        done

        # Rename file
        # smack label setting isn't needed.
        # (Because not remove/add new file, but just rename file)
        mv "${CKM_DATA_PATH}/key-${uid}-${idx_max}" "${CKM_DATA_PATH}/key-${uid}"
        if [ -f "${CKM_DATA_PATH}/key-${uid}-${idx_submax}" ]
        then
            mv "${CKM_DATA_PATH}/key-${uid}-${idx_submax}" "${CKM_DATA_PATH}/key-backup-${uid}"
        fi

        # [Optional] Remove other key-<uid>-<numeric> files.
        for file in `ls ${CKM_DATA_PATH} | grep "^key-${uid}-[0-9]*$"`
        do
            rm ${CKM_DATA_PATH}/${file}
        done
    done
}

if [ ! -f ${VERSION_INFO_PATH} ]
then
    echo "CKM VERSION_INFO NOT EXIST."
    echo "$CURRENT_VERSION" > $VERSION_INFO_PATH
    migrate_from_0_to_1
fi
