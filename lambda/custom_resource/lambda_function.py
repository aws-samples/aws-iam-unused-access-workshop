#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import boto3
import cfnresponse
import logging
import os
import json


logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3bucket = os.environ["S3BUCKET"]
s3key = os.environ["S3KEY"]
workshop_role_exception = os.environ["WORKSHOP_ROLE_EXCEPTION"]
admin_role_exception = os.environ["ADMIN_ROLE_EXCEPTION"]
workshop_lambda_unused_exception = os.environ["WORKSHOP_LAMBDA_UNUSED_EXCEPTION"]
workshop_lambda_custom_exception = os.environ["WORKSHOP_LAMBDA_CUSTOM_EXCEPTION"]

client_s3 = boto3.client("s3")

unused_access_exception_list_principal_arns = [
    workshop_role_exception,
    admin_role_exception,
    workshop_lambda_custom_exception,
    workshop_lambda_unused_exception,
]


def lambda_handler(event, context):
    logger.info(f"### RAW Event {json.dumps(event)}")
    with open(r"/tmp/" + s3key, "w") as fp:
        fp.write(
            "\n".join(str(item) for item in unused_access_exception_list_principal_arns)
        )
    client_s3.upload_file("/tmp/" + s3key, s3bucket, s3key)
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {"Response": "Success"})
