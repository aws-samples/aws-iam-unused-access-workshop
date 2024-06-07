#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import (
    App,
)

from workshop_stack import UnusedWorkshopStack

app = App()

_WorkshopStack = UnusedWorkshopStack(
    app,
    "UnusedWorkshopStack",
    stack_name="UnusedWorkshopStack"
)

app.synth()
