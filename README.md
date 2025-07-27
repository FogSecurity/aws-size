# aws-size
Checks Hard to Find Size Limits and Usage for AWS, including IAM.

For support or questions, we can be reached at info@fogsecurity.io.

## Overview

AWS services and resources have limits that can impact development.  These limits (sometimes referred to as Service Quotas) can sometimes be adjustable (soft limits) or not (hard limits).  In some cases, these can make development difficult.  

Currently, this tool focuses on AWS resources including IAM and visibility into some of those limits that can impede development.  

Imagine a scenario where someone is trying to apply least privilege and has appropriately used condition keys, granular IAM actions, and resources in their IAM policies.  They may need to add another statement or action, but if they're out of character space - they will need to think creatively on how to adjust the policy.  This tool will help bring visibility into those limits.

## Running aws-size

Prerequisites:
* Python
* AWS Credentials

To install required libraries, `pip3 install -r requirements.txt` can be run.

To run aws-size, the following command can be run:

```
python3 aws-size.py --profile <your_profile_here>
```

This will output a list of customer managed policies with usage limit over 90%.

Example output:

```
Customer Managed Policies Scanned: 82
Customer Managed Policies with usage over 90%: 2

List of policies with more than 90% character usage: 
arn:aws:iam::123412341234:policy/<bigpolicy>
Policy Usage: 90.48%
Characters Left: 585
```

## Coverage

### IAM Managed Policies

Current Limit: 6,144 characters.  

Note: white space doesn't count.

aws-size will check all customer managed policies.



Check AWS Documentation for all of the IAM and AWS STS Quotas (Limits) [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).
