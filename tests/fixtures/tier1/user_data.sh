#!/bin/bash
yum install -y nginx
export LOG_LEVEL=info
export GITHUB_TOKEN={{CANARY:ec2}}
echo "db_password = {{PASSWORD:ec2}}" > /etc/app.conf
systemctl start nginx
