# aws-size
Checks Hard to Find Size Limits and Usage for AWS

For support or questions, we can be reached at info@fogsecurity.io.

## Overview

AWS services and resources have limits that can impact development.  These limits (sometimes referred to as Service Quotas) can sometimes be adjustable (soft limits) or not (hard limits).  In some cases, these can make development difficult.  

Currently, this tool focuses on AWS IAM and visibility into some of those limits that can impede development.  

Imagine a scenario where someone is trying to apply least privilege and has appropriately used condition keys, granular IAM actions, and resources in their IAM policies.  They may need to add another statement or action, but if they're out of character space - they will need to think creatively on how to adjust the policy.  This tool will help bring visibility into those limits.

## Running aws-size



## Coverage

### IAM Managed Policies

Current Limit: 6,144 characters.  

Note: white space doesn't count.

aws-size will check all customer managed policies.



Check AWS Documentation for all of the IAM and AWS STS Quotas (Limits) [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).