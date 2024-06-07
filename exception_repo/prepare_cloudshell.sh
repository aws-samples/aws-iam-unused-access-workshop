#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
echo "------ configuring cloudshell environment -------"
sudo dnf install python3.11
pip3 install git-remote-codecommit --user --quiet
git clone codecommit://unused_workshop_repo
cd unused_workshop_repo/
/usr/bin/python3.11 -m venv .venv
. .venv/bin/activate
.venv/bin/pip3 install -r requirements.txt --quiet
git config --global user.email "participant@example.com"
git config --global user.name "Participant"
echo "------ cloudshell environment configured -------"
python3 --version
aws --version
echo ${VIRTUAL_ENV}
echo "------------ execute manually ------------------"
echo "cd unused_workshop_repo"
echo "source .venv/bin/activate"
echo "------------------------------------------------"