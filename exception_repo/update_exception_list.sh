#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
EXCEPTION_FILE_NAME="allowlist.txt"
printf "\nRoles to add to exception list file: ${EXCEPTION_FILE_NAME}\n"
BUCKET=$(aws s3api list-buckets | jq -r '.Buckets[].Name' | grep "unusedworkshopstack-allpurposes3bucket")
aws s3api get-object --bucket ${BUCKET} --key ${EXCEPTION_FILE_NAME} .temp > /dev/null
printf "\n------------------------\n"
cat .temp
rm .temp
aws iam list-roles | jq -r '.Roles[].Arn' | grep "UnusedWorkshopStack-ManageExceptionList"
printf "\n------------------------\n"