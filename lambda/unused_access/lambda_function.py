#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import boto3
from datetime import datetime, timedelta, timezone
import json
import logging
import os
import sys
import traceback
from uuid import uuid4


logger = logging.getLogger()
logger.setLevel(logging.INFO)

snstopic = os.environ["SNS_TOPIC_ARN"]
s3bucket = os.environ["BUCKET"]
s3key = os.environ["KEY"]
aws_region = os.environ["AWS_REGION"]
max_age = os.environ["MAX_AGE"]


def pull_exception_list(s3bucket_name, s3key_name):
    logger.info(
        f"#pull_exception_list# S3 Bucket {s3bucket_name} | S3 Key {s3key_name}"
    )
    client_s3 = boto3.client("s3", region_name=aws_region)
    s3object = client_s3.get_object(Bucket=s3bucket_name, Key=s3key_name)
    arn_exception_list = s3object["Body"].read().decode("UTF-8").splitlines()
    return arn_exception_list


def get_finding_data(analyzer, findind_id):
    logger.info(f"#get_finding_data# finding id {findind_id} analyzer {analyzer}")
    client_accessanalyzer = boto3.client("accessanalyzer", region_name=aws_region)
    response = client_accessanalyzer.get_finding_v2(
        analyzerArn=analyzer,
        id=findind_id,
    )
    return response


def extract_finding_data(finding_data):
    # logger.info(f"#extract_finding_data# response {response}")
    resource_arn = finding_data["resource"]
    status = finding_data["status"]
    created_at = finding_data["createdAt"]
    resource_type = finding_data["resourceType"]
    finding_type = finding_data["findingType"]
    resource_owner_account = finding_data["resourceOwnerAccount"]
    analysis_time = finding_data["analyzedAt"]
    updated_at = finding_data["updatedAt"]
    finding_details = finding_data["findingDetails"]
    return (
        resource_arn,
        status,
        created_at,
        resource_type,
        finding_type,
        resource_owner_account,
        analysis_time,
        updated_at,
        finding_details,
    )


def send_notification(
    analyzer,
    findind_id,
    resource_arn,
    status,
    created_at,
    resource_type,
    finding_type,
    resource_owner_account,
    analysis_time,
    updated_at,
    triage_results,
    remediation_completed,
    max_age,
):
    client_sns = boto3.client("sns", region_name=aws_region)
    reminder = ""
    if remediation_completed == "None":
        reminder = "| Consider refining permissions, or adding resource to exception list before maximum age is reached."
    elif remediation_completed == "Error":
        reminder = "| An error occurred during remediation."
    message = (
        f"Resource ARN {resource_arn} \n\n"
        f"Remediation executed: {remediation_completed} {reminder} \n\n"
        f"Parsed finding details: \n{triage_results} \n\n"
        f"Maximum age: {max_age} days \n\n"
        f"Analyzer {analyzer} \n\n"
        f"Finding id {findind_id} \n\n"
        f"Status: {status} \n\n"
        f"Finding created at: {created_at} \n\n"
        f"Resource Type: {resource_type} \n\n"
        f"Finding Type: {finding_type} \n\n"
        f"Resource Owner Account: {resource_owner_account} \n\n"
        f"Analysis Time: {analysis_time} \n\n"
        f"Updated at: {updated_at} \n\n"
    )
    subject = f"Unused finding"
    response = ""
    try:
        response = client_sns.publish(
            TopicArn=snstopic,
            Message=message,
            Subject=subject,
        )
    except Exception as _exp:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        logger.error(
            json.dumps(
                {
                    "errorType": exception_type.__name__,
                    "errorMessage": str(exception_value),
                    "stackTrace": traceback.format_exception(
                        exception_type, exception_value, exception_traceback
                    ),
                },
                indent=4,
            )
        )
    logger.info(f"#send_notification# {message}")
    return message


def has_matured(last_accessed):
    # remove microseconds to match format of lastAccessed element
    # {'lastAccessed': datetime.datetime(2023, 5, 18, 22, 22, 10, tzinfo=tzutc())}
    t1 = datetime.now(timezone.utc).replace(microsecond=0)
    t2 = last_accessed["lastAccessed"]
    difference = t1 - t2
    # logger.info(
    #     f"#has_matured# now={t1} | last={t2} | difference={difference} | maximum age={max_age}"
    # )
    # now=2024-05-24 03:56:32+00:00 last=2023-05-18 22:22:10+00:00 difference=371 days, 5:34:22
    return difference > timedelta(days=int(max_age)), difference


def creation_date_maturity(resource_name, resource_type, access_key, max_age):
    client = boto3.client("iam", region_name=aws_region)
    current_date = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if resource_type == "IAM User":
            response = client.get_user(UserName=resource_name)
            create_date = response["User"]["CreateDate"]
        elif resource_type == "IAM Role":
            response = client.get_role(RoleName=resource_name)
            create_date = response["Role"]["CreateDate"]
        elif resource_type == "IAM User Access Key":
            response = client.list_access_keys(UserName=resource_name)
            for key in response["AccessKeyMetadata"]:
                # logger.info(f"#creation_date_maturity# key {key}  access key {access_key}")
                if access_key == key["AccessKeyId"]:
                    create_date = key["CreateDate"]
        elif resource_type == "IAM User Password":
            response = client.get_login_profile(UserName=resource_name)
            create_date = response["LoginProfile"]["CreateDate"]
        else:
            logger.info(f"#creation_date_maturity# Unknown resource type {resource_type}")
            create_date = current_date
        difference = current_date - create_date
    except Exception as _exp:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        logger.error(
            json.dumps(
                {
                    "errorType": exception_type.__name__,
                    "errorMessage": str(exception_value),
                    "stackTrace": traceback.format_exception(
                        exception_type, exception_value, exception_traceback
                    ),
                },
                indent=4,
            )
        )
        create_date = current_date
        difference = current_date - create_date
    # logger.info(
    #     f"#creation_date_maturity# current date={current_date} | create date={create_date} | difference={difference} | maximum age={max_age}"
    # )
    # logger.info(f"{resource_name} | {resource_type}, {access_key}, {max_age}")
    return create_date, difference > timedelta(days=int(max_age)), difference


def parse_finding(finding_type, resource_arn, finding_details, arn_exception_list, resource_type):
    # logger.info(
    #     f"#parse_finding# finding type {finding_type} | resource_arn {resource_arn} | finding_details {finding_details} | arn_exception_list {arn_exception_list}"
    # )
    reached_max_age = False
    services_not_used = []
    services_aging = []
    aks_age = []
    parse_results = "Not Parsed"
    created_date = ""
    if finding_type == "UnusedPermission":
        for detail in finding_details:
            if "lastAccessed" in detail["unusedPermissionDetails"]:
                reached_max_age, difference = has_matured(
                    detail["unusedPermissionDetails"]
                )
                services_aging.append(
                    {
                        "name": detail["unusedPermissionDetails"]["serviceNamespace"],
                        "age": difference,
                        "aged": reached_max_age,
                    }
                )
            else:
                if resource_type == "AWS::IAM::User":
                    rtype = "IAM User"
                elif resource_type == "AWS::IAM::Role":
                    rtype = "IAM Role"
                else:
                    rtype = "Unknown"
                created_date, reached_max_age, difference = creation_date_maturity(
                    resource_arn.rsplit("/", 1)[-1],
                    rtype,
                    "",
                    max_age,
                )
                services_not_used.append(
                    {
                        "name": detail["unusedPermissionDetails"]["serviceNamespace"],
                        "age": difference,
                        "aged": reached_max_age,
                    }
                )
        parse_results_aging = ""
        parse_results_not_used = ""
        if services_aging:
            parse_results_aging = f"Services been unused: "
            for service in services_aging:
                parse_results_aging = (
                    parse_results_aging
                    + f"{service['name']} | last used={service['age']} | >{max_age} days={service['aged']} || "
                )
        if services_not_used:
            parse_results_not_used = f"Services never been used: "
            for service in services_not_used:
                parse_results_not_used = (
                    parse_results_not_used
                    + f"{service['name']} | last used={service['age']} | >{max_age} days={service['aged']} || "
                )
        parse_results = parse_results_aging + " \n\n" + parse_results_not_used
    elif finding_type == "UnusedIAMRole":
        if "lastAccessed" in finding_details[0]["unusedIamRoleDetails"]:
            reached_max_age, difference = has_matured(
                finding_details[0]["unusedIamRoleDetails"]
            )
            parse_results = f"Role has not been used for {difference} days"
        else:
            created_date, reached_max_age, difference = creation_date_maturity(
                resource_arn.rsplit("/", 1)[-1],
                "IAM Role",
                "",
                max_age,
            )
            parse_results = (
                f"IAM Role has never been used. It was created on {created_date}"
            )
    elif finding_type == "UnusedIAMUserAccessKey":
        parse_results = f"Access Key(s) "
        i = 0
        for ak in finding_details:
            aks_age.append(
                {
                    "access_key_id": ak["unusedIamUserAccessKeyDetails"]["accessKeyId"],
                    "aged": False,
                    "age": 0,
                }
            )
            if "lastAccessed" in finding_details[0]["unusedIamUserAccessKeyDetails"]:
                reached_max_age, difference = has_matured(
                    finding_details[0]["unusedIamUserAccessKeyDetails"]
                )
                aks_age[i]["aged"] = reached_max_age
                aks_age[i]["age"] = difference
            else:
                create_date, reached_max_age, difference = creation_date_maturity(
                    resource_arn.rsplit("/", 1)[-1],
                    "IAM User Access Key",
                    ak["unusedIamUserAccessKeyDetails"]["accessKeyId"],
                    max_age,
                )
                aks_age[i]["aged"] = reached_max_age
                aks_age[i]["age"] = difference
            parse_results = parse_results + f"{ak} age is {difference} | "
            i = i + 1
        # logger.info(f"#parse_finding# aks_age {aks_age}")
    elif finding_type == "UnusedIAMUserPassword":
        if "lastAccessed" in finding_details[0]["unusedIamUserPasswordDetails"]:
            reached_max_age, difference = has_matured(
                finding_details[0]["unusedIamUserPasswordDetails"]
            )
            parse_results = f"IAM User password has not been used for {difference} days"
        else:
            created_date, reached_max_age, difference = creation_date_maturity(
                resource_arn.rsplit("/", 1)[-1],
                "IAM User Password",
                "",
                max_age,
            )
            parse_results = f"IAM User password has never been used. It was created on {created_date}"
    else:
        logger.info(f"#parse_finding# Unknown finding type {finding_type}")
    in_exception_list = resource_arn in arn_exception_list
    return (
        parse_results,
        in_exception_list,
        services_aging,
        services_not_used,
        aks_age,
        reached_max_age,
        created_date,
    )


def remediate(
    finding_type,
    resource_arn,
    services_aging,
    services_not_used,
    aks_age,
    in_exception_list,
    status,
    reached_max_age,
):
    try:
        remediation_completed = "None"
        response = "No remediation calls made"
        if (not in_exception_list) and (status == "ACTIVE"):
            client = boto3.client("iam", region_name=aws_region)
            if finding_type == "UnusedPermission":
                role_name = resource_arn.rsplit("/", 1)[-1]
                actions = []
                for service in services_aging:
                    if service["aged"]:
                        actions.append(f'{service["name"]}:*')
                for service in services_not_used:
                    if service["aged"]:
                        actions.append(f'{service["name"]}:*')
                new_actions = []
                deny_policy = {
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Deny",
                        "Action": new_actions,
                        "Resource": "*",
                    },
                }
                if len(actions) != 0:
                    while len(actions) != 0:
                        new_actions.append(actions[0])
                        last_element = actions[0]
                        actions.pop(0)
                        if len(str(new_actions)) > 10240:
                            actions.append(last_element)
                            new_actions.pop()
                            response = client.put_role_policy(
                                PolicyDocument=json.dumps(deny_policy),
                                PolicyName="UnusedAccess-" + str(uuid4()),
                                RoleName=role_name,
                            )
                            logger.info(f"#remediate# response from API call {response}")
                            new_actions = []
                    remediation_completed = f"Unused services have been denied in an inline policy attached to the IAM Role"
            elif finding_type == "UnusedIAMRole":
                if reached_max_age:
                    role_name = resource_arn.rsplit("/", 1)[-1]
                    # Disable the IAM Role
                    response = client.put_role_policy(
                        PolicyDocument='{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}',
                        PolicyName="UnusedAccess-" + str(uuid4()),
                        RoleName=role_name,
                    )
                    logger.info(f"#remediate# response from API call {response}")
                    remediation_completed = (
                        f"IAM Role disabled via inline deny all policy"
                    )
                    # Delete the IAM Role
                    # response = client.delete_role(
                    #      RoleName=role_name,
                    # )
                    # remediation_completed = (
                    #     f"IAM Role {role_name} deleted"
                    # )
            elif finding_type == "UnusedIAMUserAccessKey":
                if reached_max_age:
                    user_name = resource_arn.rsplit("/", 1)[-1]
                    remediation_completed = f"IAM User Access Key "
                    for ak in aks_age:
                        if ak["aged"]:
                            # Deactivate Access Key
                            response = client.update_access_key(
                                AccessKeyId=ak["access_key_id"],
                                Status="Inactive",
                                UserName=user_name,
                            )
                            logger.info(f"#remediate# response from API call {response}")
                            remediation_completed = (
                                remediation_completed
                                + f'{ak["access_key_id"]} deactivated | '
                            )
                            # Delete Access Key
                            # response = client.delete_access_key(
                            #     AccessKeyId=ak,
                            #     UserName=user_name,
                            # )
                            # remediation_completed = remediation_completed + f'{ak["access_key_id"]} deleted | '
            elif finding_type == "UnusedIAMUserPassword":
                if reached_max_age:
                    user_name = resource_arn.rsplit("/", 1)[-1]
                    response = client.delete_login_profile(UserName=user_name)
                    remediation_completed = f"IAM User console access removed"
            else:
                remediation_completed = "None"
                logger.info(f"Unknown finding type {finding_type}")
        else:
            remediation_completed = (
                f"None, resource found in exception list."
            )
    except Exception as _exp:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        logger.error(
            json.dumps(
                {
                    "errorType": exception_type.__name__,
                    "errorMessage": str(exception_value),
                    "stackTrace": traceback.format_exception(
                        exception_type, exception_value, exception_traceback
                    ),
                },
                indent=4,
            )
        )
        remediation_completed = "Error"
    return remediation_completed


def lambda_handler(event, context):
    """Lambda Handler"""
    logger.info(f"#lambda_handler# event received {json.dumps(event, indent=4)}")
    iam_principal_exception_list = pull_exception_list(s3bucket, s3key)
    unused_findind_id = event["detail"]["findingId"]
    unused_analyzer = event["resources"][0]
    finding_data = get_finding_data(unused_analyzer, unused_findind_id)
    (
        resource_arn,
        status,
        created_at,
        resource_type,
        finding_type,
        resource_owner_account,
        analysis_time,
        updated_at,
        finding_details,
    ) = extract_finding_data(finding_data)

    (
        parse_results,
        in_exception_list,
        services_aging,
        services_not_used,
        aks_age,
        reached_max_age,
        create_date,
    ) = parse_finding(
        finding_type,
        resource_arn,
        finding_details,
        iam_principal_exception_list,
        resource_type,
    )

    remediation_completed = remediate(
        finding_type,
        resource_arn,
        services_aging,
        services_not_used,
        aks_age,
        in_exception_list,
        status,
        reached_max_age,
    )

    message = send_notification(
        unused_analyzer,
        unused_findind_id,
        resource_arn,
        status,
        created_at,
        resource_type,
        finding_type,
        resource_owner_account,
        analysis_time,
        updated_at,
        parse_results,
        remediation_completed,
        max_age,
    )
