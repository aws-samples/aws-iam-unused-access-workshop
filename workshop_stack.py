# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from aws_cdk import (
    Aws,
    Stack,
    BundlingOptions,
    CfnOutput,
    CfnParameter,
    CustomResource,
    Duration,
    SecretValue,
    aws_accessanalyzer,
    aws_codecommit,
    aws_codebuild,
    aws_codepipeline,
    aws_codepipeline_actions,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_lambda,
    aws_secretsmanager,
    aws_sns,
    aws_sns_subscriptions,
    aws_sqs,
    aws_ssm,
    aws_s3,
)

from constructs import Construct


class UnusedWorkshopStack(Stack):
    def __init__(
            self,
            scope: Construct,
            construct_id: str,
            **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        workshop_participant_role = CfnParameter(
            self,
            "WorkshopParticipantRoleParam",
            type="String",
            description="Name of Workshop Studio Role",
            default="WSParticipantRole",
        )

        # The default is set to 120 days which should be higher than the tracking
        # period of the analyzer to allow for exceptions to be created.
        max_age = CfnParameter(
            self,
            "MaxAgeParam",
            type="Number",
            description="Maximum age of unused access in days",
            default=120,
        )

        # The default is set to 1 day to facilitate the workshop, that should be set
        # to a higher value for testing purposes such as 90 days.
        access_analyzer_tracking = CfnParameter(
            self,
            "DaysTrackingParam",
            type="Number",
            description="Tracking period for Unused Access Analyzer",
            default=1,
        )

        unused_exceptions_file_name = CfnParameter(
            self,
            "UnusedExceptionsFileNameParam",
            type="String",
            description="Name of the file containing the exception list for unused access",
            default="allowlist.txt",
        )

        console_password = aws_secretsmanager.Secret(
            self,
            "ConsolePassword",
            secret_name="ConsolePassword",
            generate_secret_string=aws_secretsmanager.SecretStringGenerator(
                secret_string_template='{"username":"UnusedUserConsole"}',
                generate_string_key="password",
                password_length=16,
                exclude_punctuation=True,
            ),
        )

        unused_user_console = aws_iam.User(
            self,
            "UnusedUserConsole",
            user_name="UnusedUserConsole",
            password=SecretValue.secrets_manager(console_password.secret_name),
        )

        unused_user_access_keys = aws_iam.User(
            self,
            "UnusedUserAccessKeys",
            user_name="UnusedUserAccessKeys",
        )

        unused_access_key = aws_iam.AccessKey(
            self,
            "UnusedAccessKey",
            user=unused_user_access_keys,
            status=aws_iam.AccessKeyStatus.ACTIVE,
        )

        unused_role = aws_iam.Role(
            self,
            "UnusedRole",
            role_name="UnusedRole",
            assumed_by=aws_iam.AccountPrincipal(
                account_id=Aws.ACCOUNT_ID
            ).with_conditions(
                {"StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/" + workshop_participant_role.value_as_string
                    ]
                }
                }
            )
        )

        unused_role_forensics = aws_iam.Role(
            self,
            "Forensics",
            role_name="Forensics",
            assumed_by=aws_iam.AccountPrincipal(
                account_id=Aws.ACCOUNT_ID
            ).with_conditions(
                {"StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/" + workshop_participant_role.value_as_string
                    ]
                }
                }
            )
        )

        unused_role_permissions_policy = aws_iam.ManagedPolicy(
            self,
            "UnusedRolePermissionsPolicy",
            statements=[
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                        "ec2:DescribeInstances",
                        "ec2:DescribeRegions",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeVpcs",
                    ],
                    resources=[
                        "*"
                    ],
                ),
            ]
        )

        unused_role_permissions = aws_iam.Role(
            self,
            "UnusedRoleUnusedPermissions",
            role_name="UnusedRoleUnusedPermissions",
            managed_policies=[unused_role_permissions_policy],
            assumed_by=aws_iam.AccountPrincipal(
                account_id=Aws.ACCOUNT_ID
            ).with_conditions(
                {"StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/" + workshop_participant_role.value_as_string
                    ]
                }
                }
            )
        )

        all_purpose_bucket = aws_s3.Bucket(
            self,
            "AllPurposeS3Bucket",
            block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL,
            encryption=aws_s3.BucketEncryption.S3_MANAGED,
        )

        sns_topic_name = CfnParameter(
            self,
            "SNSTopicParam",
            type="String",
            description="Name of the SNS Topic for notifications",
            default="IAMAccessAnalyzerFindingNotifications",
        )

        analyzer_name = CfnParameter(
            self,
            "AnalyzerNameParam",
            type="String",
            description="Name of the Analyzer",
            default="unused-workshop-analyzer",
        )

        access_analyzer_analyzer = aws_accessanalyzer.CfnAnalyzer(
            self,
            "AccessAnalyzerAnalyzer",
            analyzer_name=analyzer_name.value_as_string,
            type="ACCOUNT_UNUSED_ACCESS",
            analyzer_configuration=aws_accessanalyzer.CfnAnalyzer.AnalyzerConfigurationProperty(
                unused_access_configuration=aws_accessanalyzer.CfnAnalyzer.UnusedAccessConfigurationProperty(
                    unused_access_age=access_analyzer_tracking.value_as_number,
                )
            ),
        )

        sns_topic = aws_sns.Topic(
            self,
            "SNSTopicNotifications",
            topic_name=sns_topic_name.value_as_string,
        )

        lambda_custom_resource_role_policy = aws_iam.ManagedPolicy(
            self,
            "LambdaCustomResourceRolePolicy",
            statements=[
                aws_iam.PolicyStatement(
                    sid="AllowS3",
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                        "s3:PutObject",
                    ],
                    resources=[
                        all_purpose_bucket.bucket_arn,
                        all_purpose_bucket.bucket_arn
                        + "/"
                        + unused_exceptions_file_name.value_as_string,
                    ],
                ),
            ],
        )

        lambda_custom_resource_role = aws_iam.Role(
            self,
            "LambdaCustomResourceRole",
            role_name="LambdaCustomResourceRole",
            managed_policies=[
                lambda_custom_resource_role_policy,
                aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            assumed_by=aws_iam.CompositePrincipal(
                aws_iam.ServicePrincipal("lambda.amazonaws.com"),
                aws_iam.AccountPrincipal(account_id=Aws.ACCOUNT_ID)
            ),
        )

        lambda_unused_access_role_policy = aws_iam.ManagedPolicy(
            self,
            "LambdaUnusedAccessRolePolicy",
            statements=[
                aws_iam.PolicyStatement(
                    sid="CloudWatchLogsWritePermissions",
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    resources=[
                        "arn:aws:logs:"
                        + Aws.REGION
                        + ":"
                        + Aws.ACCOUNT_ID
                        + ":log-group:/*"
                    ],
                ),
                aws_iam.PolicyStatement(
                    sid="IAMPermissions",
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                        "iam:PutRolePolicy",
                        "iam:UpdateAccessKey",
                        "iam:DeleteLoginProfile",
                        "iam:DeleteAccessKey",
                        "iam:DeleteUser",
                        "iam:DeleteRole",
                        "iam:DeleteLoginProfile",
                        "iam:ListAccessKeys",
                        "iam:GetLoginProfile",
                        "iam:GetRole",
                        "iam:GetUser",
                    ],
                    resources=["*"],
                ),
                aws_iam.PolicyStatement(
                    sid="SNSPublishAllow",
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                        "sns:Publish",
                    ],
                    resources=[sns_topic.topic_arn],
                ),
                aws_iam.PolicyStatement(
                    sid="AccessAnalyzerPermissions",
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                        "access-analyzer:GetFinding",
                        "access-analyzer:GetFindingV2",
                    ],
                    resources=["*"],
                ),
                aws_iam.PolicyStatement(
                    sid="AllowS3",
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                        "s3:GetObject",
                    ],
                    resources=[
                        all_purpose_bucket.bucket_arn,
                        all_purpose_bucket.bucket_arn
                        + "/"
                        + unused_exceptions_file_name.value_as_string,
                    ],
                ),
            ],
        )

        lambda_unused_access_role = aws_iam.Role(
            self,
            "LambdaUnusedAccessRole",
            assumed_by=aws_iam.ServicePrincipal(service="lambda.amazonaws.com"),
            managed_policies=[lambda_unused_access_role_policy],
        )

        lambda_unused_access_function = aws_lambda.Function(
            self,
            "LambdaUnusedAccessFunction",
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            handler='lambda_function.lambda_handler',
            code=aws_lambda.Code.from_asset(
                "./lambda/unused_access/",
                bundling=BundlingOptions(
                    image=aws_lambda.Runtime.PYTHON_3_11.bundling_image,
                    command=[
                        "bash", "-c",
                        "pip install --no-cache -r requirements.txt -t /asset-output && cp -au . /asset-output"
                    ]
                )
            ),
            timeout=Duration.seconds(300),
            role=lambda_unused_access_role,
            environment={
                "SNS_TOPIC_ARN": sns_topic.topic_arn,
                "BUCKET": all_purpose_bucket.bucket_name,
                "KEY": unused_exceptions_file_name.value_as_string,
                "MAX_AGE": str(max_age.value_as_number),
            },
        )

        CfnOutput(
            self,
            "LambdaUnusedAccessFunctionArn",
            description="ARN for the lambda function performing scanning for unused_access actions",
            value=lambda_unused_access_function.function_arn,
        )

        CfnOutput(
            self,
            "LambdaUnusedAccessRolePolicyArn",
            description="ARN for the role policy used by the Lambda function",
            value=lambda_unused_access_role_policy.managed_policy_arn,
        )

        eventbridge_rule = aws_events.Rule(
            self,
            "EventBridgeRule",
            event_pattern=aws_events.EventPattern(
                source=["aws.access-analyzer"],
                detail_type=["Unused Access Finding for IAM entities"],
            ),
        )

        eventbridge_rule.add_target(
            aws_events_targets.LambdaFunction(
                lambda_unused_access_function,
            ),
        )

        lambda_custom_resource_function = aws_lambda.Function(
            scope=self,
            id="LambdaCustomResourceFunction",
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            handler='lambda_function.lambda_handler',
            role=lambda_custom_resource_role,
            timeout=Duration.seconds(60),
            code=aws_lambda.Code.from_asset(
                "./lambda/custom_resource/",
                bundling=BundlingOptions(
                    image=aws_lambda.Runtime.PYTHON_3_11.bundling_image,
                    command=[
                        "bash", "-c",
                        "pip install --no-cache -r requirements.txt -t /asset-output && cp -au . /asset-output"
                    ]
                )
            ),
            environment={
                "S3BUCKET": all_purpose_bucket.bucket_name,
                "S3KEY": unused_exceptions_file_name.value_as_string,
                "WORKSHOP_ROLE_EXCEPTION": "arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/" + workshop_participant_role.value_as_string,
                "ADMIN_ROLE_EXCEPTION": "arn:aws:iam::" + Aws.ACCOUNT_ID + ":role/Admin",
                "WORKSHOP_LAMBDA_UNUSED_EXCEPTION": lambda_unused_access_role.role_arn,
                "WORKSHOP_LAMBDA_CUSTOM_EXCEPTION": lambda_custom_resource_role.role_arn,
            },
        )

        CustomResource(
            self,
            "CustomResourceLambda",
            service_token=lambda_custom_resource_function.function_arn,
        )

        CfnOutput(
            self,
            "BucketArn",
            description="ARN of the S3 bucket to be used for all purposes",
            value=all_purpose_bucket.bucket_arn,
        )

        CfnOutput(
            self,
            "TopicArn",
            description="ARN of the SNS Topic for notifications",
            value=sns_topic.topic_arn,
        )

        CfnOutput(
            self,
            "AnalyzerARN",
            description="ARN for Analyzer",
            value=access_analyzer_analyzer.attr_arn,
        )

        code_repository = aws_codecommit.Repository(
            self,
            "CodeRepository",
            repository_name="unused_workshop_repo",
            code=aws_codecommit.Code.from_directory("exception_repo", "main"),
        )

        manage_exception_list = aws_codebuild.Project(
            self,
            "ManageExceptionList",
            environment=aws_codebuild.BuildEnvironment(
                privileged=True,
                build_image=aws_codebuild.LinuxBuildImage.AMAZON_LINUX_2_5,
                environment_variables={
                    "AWS_REGION": aws_codebuild.BuildEnvironmentVariable(
                        value=Aws.REGION
                    ),
                    "AWS_ACCOUNT_ID": aws_codebuild.BuildEnvironmentVariable(
                        value=Aws.ACCOUNT_ID
                    ),
                    "BUCKET": aws_codebuild.BuildEnvironmentVariable(
                        value=all_purpose_bucket.bucket_name
                    ),
                    "KEY": aws_codebuild.BuildEnvironmentVariable(
                        value=unused_exceptions_file_name.value_as_string
                    ),
                    "ANALYZER_NAME": aws_codebuild.BuildEnvironmentVariable(
                        value=access_analyzer_analyzer.analyzer_name
                    ),
                    "ANALYZER_ARN": aws_codebuild.BuildEnvironmentVariable(
                        value=access_analyzer_analyzer.attr_arn
                    ),
                },
            ),
            source=aws_codebuild.Source.code_commit(
                repository=code_repository, branch_or_ref="main"
            ),
            build_spec=aws_codebuild.BuildSpec.from_object(
                {
                    "version": "0.2",
                    "phases": {
                        "install": {
                            "commands": [
                                "curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip",
                                "unzip awscliv2.zip > /dev/null 2>&1",
                                "sudo ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update",
                                "export PATH=/usr/local/bin:$PATH",
                            ]
                        },
                        "build": {
                            "commands": [
                                "echo $PATH",
                                "echo $AWS_REGION",
                                "echo $AWS_ACCOUNT_ID",
                                "echo $BUCKET",
                                "echo $KEY",
                                "echo $ANALYZER_NAME",
                                "echo $ANALYZER_ARN",
                                "aws sts get-caller-identity",
                                "aws --version",
                                "ls -lah",
                                "aws s3api get-object --bucket ${BUCKET} --key ${KEY} from_s3_${KEY}",
                                "cat from_s3_$KEY",
                                "cat $KEY",
                                "aws accessanalyzer list-analyzers",
                                "aws accessanalyzer list-archive-rules --analyzer-name $ANALYZER_NAME",
                            ]
                        },
                    },
                }
            ),
        )

        code_repository.grant_pull(manage_exception_list)

        manage_exception_list.add_to_role_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "access-analyzer:ApplyArchiveRule",
                    "access-analyzer:CreateArchiveRule",
                    "access-analyzer:ListArchiveRules",
                    "access-analyzer:ListAnalyzers",
                ],
                resources=["*"],
                effect=aws_iam.Effect.ALLOW,
            ),
        )

        manage_exception_list.add_to_role_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:PutObject",
                ],
                resources=[
                    all_purpose_bucket.bucket_arn,
                    all_purpose_bucket.bucket_arn
                    + "/"
                    + unused_exceptions_file_name.value_as_string,
                ],
                effect=aws_iam.Effect.ALLOW,
            ),
        )

        manage_exception_list.add_to_role_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "iam:CreateServiceLinkedRole",
                ],
                resources=["*"],
                effect=aws_iam.Effect.ALLOW,
                conditions={
                    "StringEquals": {
                        "iam:AWSServiceName": "access-analyzer.amazonaws.com"
                    }
                },
            )
        )

        source_artifact = aws_codepipeline.Artifact("SourceArtifact")
        build_artifact = aws_codepipeline.Artifact("BuildArtifact")

        source_stage = aws_codepipeline.StageProps(
            stage_name="Source",
            actions=[
                aws_codepipeline_actions.CodeCommitSourceAction(
                    action_name="CodeCommit",
                    branch="main",
                    output=source_artifact,
                    repository=code_repository,
                )
            ],
        )

        build_stage = aws_codepipeline.StageProps(
            stage_name="Build",
            actions=[
                aws_codepipeline_actions.CodeBuildAction(
                    action_name="ManageExceptionList",
                    input=aws_codepipeline.Artifact("SourceArtifact"),
                    project=manage_exception_list,
                    outputs=[build_artifact],
                )
            ],
        )

        manage_exception_list_pipeline = aws_codepipeline.Pipeline(
            self,
            "ManageExceptionListPipeline",
            pipeline_type=aws_codepipeline.PipelineType.V2,
            stages=[source_stage, build_stage],
        )