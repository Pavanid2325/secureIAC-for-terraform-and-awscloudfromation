# Local AWS Security Guidance

This repository starts with a small organization-owned guidance document so the
offline ingestion and retrieval pipeline can be tested. Add authoritative AWS,
CIS, and internal policy documents to this directory before production use.

## Amazon S3

S3 buckets that store sensitive data should use server-side encryption, block
public access unless there is a documented exception, and enable access logging
where operationally appropriate.

## Amazon EC2 Security Groups

Security groups should avoid unrestricted ingress from 0.0.0.0/0, especially
for administrative ports such as SSH port 22 and RDP port 3389. Rules should be
limited to trusted CIDR ranges or managed access paths.

## AWS IAM

IAM policies should follow least privilege. Wildcard actions and wildcard
resources should be avoided unless the risk is accepted and monitored.

## Amazon RDS

RDS databases should enable storage encryption, use managed secrets or strong
credential handling, avoid public accessibility by default, and configure
backup retention according to recovery requirements.
