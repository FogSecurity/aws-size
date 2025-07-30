# aws-size
Checks Hard to Find Size Limits and Usage for AWS, including IAM.

For support or questions, we can be reached at info@fogsecurity.io.

## Overview

AWS services and resources have limits that can impact development.  These limits (sometimes referred to as Service Quotas) can sometimes be adjustable (soft limits) or not (hard limits).  In some cases, these can make development difficult as running into a limit late can result in larger or risky architectural changes.  While AWS offers tooling to manage these and view visibility such as Service Quotas, Trusted Advisor, and more - these tools do not account for all limits and often refer to account or resource # limits, not necessarily limits within resources.  Even open source tooling we looked at focuses on similar limits and Trusted Advisor coverage.  aws-size addresses this gap in coverage and visibility.

Reach out to us at info@fogsecurity.io if you have questions or feedback.

Current Coverage: IAM, Organizations, EC2

Imagine a scenario where someone is trying to apply least privilege and has appropriately used condition keys, granular IAM actions, and resources in their IAM policies.  They may need to add another statement or action, but if they're out of character space - they will need to think creatively on how to adjust the policy.  This tool will help bring visibility into those limits.  Example workarounds in IAM are using wildcards (which can be dangerous), or splitting into multiple policies.  These changes can be complex and can result in different configurations or unintended results.

## Running aws-size

Prerequisites:
* Python
* AWS Credentials

To install required libraries, `pip3 install -r requirements.txt` can be run.

To run aws-size, the following command can be run:

```
python3 aws-size.py --profile <your_profile_here> --region us-east-1
```

```
? Select a resource limit (Use arrow keys)
 » AWS IAM Managed Policies
   AWS EC2 User Data
   Organizations SCPs
   Organizations RCPs
```

Note: Region is only necessary if choosing resources that are regional such as EC2 instances and user data.  IAM is a global service.

Example output:

```
Customer Managed Policies Scanned: 82
Customer Managed Policies with usage over 90%: 2

List of policies with more than 90% character usage: 
arn:aws:iam::123412341234:policy/<bigpolicy>
Policy Usage: 90.48%
Characters Left: 585
```

### Customization: Setting Threshold

By default, aws-size reports resources with equal or over than 90% usage.  For customization, aws-size supports the `--threshold` argument.  This argument takes a number between 0 and 1 inclusive to set the threshold of resources for reporting.

For example, setting the threshold to 0.75 will report resources with 75% or more usage.  

```
python3 aws-size.py --profile <your_profile_here> --threshold 0.75
```

If you want to return all resources, set the threshold to 0.  Additionally, threshold can be set to all.

Example commands:

```
python3 aws-size.py --profile <your_profile_here> --threshold all
python3 aws-size.py --profile <your_profile_here> --threshold 0
```

## Coverage

### IAM Managed Policies (Global)

Limit: 6,144 characters  
Note: white space doesn't count  
[AWS Documentation on IAM Limits](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).

### EC2 User Data (Region Specific)

Limit: 16 KB  
Note: 16 KB is the limit for unencoded.  EC2 encodes user data  
[EC2 User Data Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html)

### AWS Organizations Service Control Policies (Global)

Limit: 5120 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### AWS Organizations Resource Control Policies (Global)

Limit: 5120 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)
