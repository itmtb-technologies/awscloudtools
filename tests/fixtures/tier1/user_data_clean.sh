#!/bin/bash
yum install -y nginx
export DB_PASSWORD_ARN=arn:aws:secretsmanager:eu-west-1:123456789012:secret:db
export TOKEN_URL=https://auth.example.com/token
systemctl start nginx
