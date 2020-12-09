#!/bin/bash

# check number of arguments
if [ ${#} -ne 2 ] ; then
    echo "Invalid number of arguments"
    echo "Usage: make_check_wrapper.sh [project_num] [iteration_num]"
    exit -1
fi

# project number
if [ ${1} -lt 1 ] || [ ${1} -gt 4 ] ; then
    echo "Invalid project number"
    echo "Valid project number: 1(threads), 2(user programs), 3(virtual memory), 4(file system)"
    exit -1
fi
NUM_PROJ=${1}

# number of iterations
if [ ${2} -lt 1 ] ; then
    echo "Invalid number of iterations"
    echo "Number of Iterations should be positive integer"
    exit -1
fi
NUM_ITER=${2}

# target directory
SH_DIR=`dirname ${0}`
SRC_DIR=${SH_DIR}/..
if [ ${NUM_PROJ} -eq 1 ] ; then
    TAR_DIR=${SRC_DIR}/threads
elif [ ${NUM_PROJ} -eq 2 ] ; then
    TAR_DIR=${SRC_DIR}/userprog
elif [ ${NUM_PROJ} -eq 3 ] ; then
    TAR_DIR=${SRC_DIR}/vm
else
    TAR_DIR=${TAR_DIR}/filesys
fi

# result directory
RES_DIR=${SRC_DIR}/result
mkdir -p ${RES_DIR}

# remove previous result file
RES_NAME=${RES_DIR}/project${NUM_PROJ}_make_check_result.txt
rm ${RES_NAME} > /dev/null 2>&1

# move current position
ORG_DIR=${PWD}
cd ${TAR_DIR}

# test and save result
for i in $(seq 1 ${NUM_ITER})
do
    FILE_NAME=${RES_DIR}/make_check_${i}.txt

    make clean
    make
    make check | tee ${FILE_NAME}
done

# save failed test name for each make check result
cd ${SH_DIR}
python3 make_check_wrapper.py ${NUM_PROJ} ${NUM_ITER} ${RES_DIR} | tee ${RES_NAME}

# remove result files
for i in $(seq 1 ${NUM_ITER})
do
    FILE_NAME=${RES_DIR}/make_check_${i}.txt
    rm ${FILE_NAME}
done

# move back to original position
cd ${ORG_DIR}
