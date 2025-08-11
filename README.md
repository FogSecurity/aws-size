# aws-size
Checks Hard to Find Size Limits and Usage for AWS and can provide advance warning to teams about resource limits in AWS before it's too late.  Usage of these limits are not covered by AWS provided tooling such as Service Quotas and Trusted Advisor.

For support or questions, we can be reached at info@fogsecurity.io.  
Release Blog: [https://www.fogsecurity.io/blog/aws-size-release](https://www.fogsecurity.io/blog/aws-size-release)  

## Overview

AWS services and resources have limits that can impact development.  These limits (sometimes referred to as Service Quotas) can sometimes be adjustable (soft limits) or not (hard limits).  In some cases, these can make development difficult as running into a limit late can result in larger or risky architectural changes.  While AWS offers tooling to manage these and view visibility such as Service Quotas, Trusted Advisor, and more - these tools do not account for all limits and often refer to account or resource # limits, not necessarily limits within resources.  Even open source tooling we looked at focuses on similar limits and Trusted Advisor coverage.  aws-size addresses this gap in coverage and visibility.

Current Coverage: IAM, Organizations, EC2, S3, Systems Manager, Lambda, Secrets Manager

Imagine a scenario where someone is trying to apply least privilege and has appropriately used condition keys, granular IAM actions, and resources in their IAM policies.  They may need to add another statement or action, but if they're out of character space - they will need to think creatively on how to adjust the policy.  This tool will help bring visibility into those limits.  Example workarounds in IAM are using wildcards (which can be dangerous), or splitting into multiple policies.  These changes can be complex and can result in different configurations or unintended results.

## Running aws-size

Prerequisites:
* Python
* AWS Credentials

We recommend least privilege when running aws-size and using short-term credentials.  aws-size does not require any sort of write permissions.  AWS provided managed policies that can work with aws-size include ReadOnlyAccess and SecurityAudit.  The ViewOnlyAccess policy does not have the appropriate permissions to view usage of certain resources.  

If you are using aws-size to scan parameter or secret resources (Secrets Manager or Systems Manager Parameter Store), AWS provided managed policies may not work.  Secrets Manager requires `secretsmanager:GetSecretValue` which is not in any of the aforementioned AWS provided managed policies.  Parameter Store requires `ssm:GetParameter` which is not in SecurityAudit nor ViewOnlyAccess.  Additionally, certain resources will require `kms:Decrypt` if encrypted with a KMS key to retrieve length of data.  

IMPORTANT: aws-size has the ability to scan for potentially sensitive information such as Lambda Environment Variables, Secrets Manager Secrets, and Parameter Store Parameters.  For accurate sizing and limit calculations, aws-size will need access to the underlying information and resource values.  We recommend ensuring access to aws-size, aws-size's credentials are secure, and that any privileged permissions used by aws-size are not shared to other unintended use cases.  Aws-size can be run without those capabilities and thus if you do not have a need or desire to scan for potentially sensitive information, we recommend ensuring those corresponding IAM permissions are not given to aws-size.  See the [IAM reference](iam/) for additional references.

If concerned about scanning secret values, we recommend not granting aws-size access to sensitive variables and only running aws-size on non-sensitive resources.

A reference IAM policy for aws-size (all features) can be found [here](iam/aws_size_read_policy.json).

To install required libraries, `pip3 install -r requirements.txt` can be run.

To run aws-size, the following command can be run:

```
python3 aws-size.py --profile <your_profile_here> --region us-east-1
```

```
? Select a resource limit (Use arrow keys)
 » AWS IAM Managed Policies
   AWS IAM Role Trust Policy
   AWS IAM Managed Policies Per Role
   AWS EC2 User Data
   S3 Bucket Policy
   Organizations SCPs
   Organizations RCPs
   Organizations Declarative Policies
   Organizations AI Services Opt-out Policies
   Organizations Tag Policies
   Organizations Backup Policies
   Organizations Chat Applications Policies
   SSM Parameter Store Parameters
   Lambda Environment Variables
   Secrets Manager Secrets
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

### Saving Output to File

aws-size now supports saving the run results to a json file via the `--output` argument. To save, use the `--output` argument followed by the file name. Results are stored with metadata from the run.

Example command:
```
python3 aws-size.py --profile <your_profile_here> --threshold 0.75 --output aws-size-output.json
```

Example of file structure is as follows:
```
{
    "metadata": {
        "resource": "AWS IAM Managed Policies",
        "threshold": 0,
        "timestamp": "2025-08-07 15:35:58"
    },
    "results": [
        {
            "arn": "arn:aws:iam::123412341234:policy/aws-size-test-policy",
            "name": "aws-size-test-policy",
            "usage": 0.0832,
            "charleft": 5633
        },
        ...
    ]
}
```


## Coverage

| Service | Resource | Limit | Limit Size | Service Quota Coverage | Service Quota Visibility | Trusted Advisor Visibility | Adjustable |
| ------- | -------- | ----- | ---------- | ---------------------- | ------------------------ | -------------------------- | ---------- |
| IAM | Managed Policies | Policy Length | 6,144 characters | L-ED111B8C | No | No | No |
| IAM | IAM Roles | Role trust policy length | 2,048 characters | L-C07B4B0D | No | Yes* | Yes |
| IAM | IAM Roles | Managed Policies Per Role | 10 | L-0DA4ABF3 | Yes | Yes | No |
| EC2 | Instance | User Data Size | 16 KB | No | No | No | No |
| S3 | Bucket | Bucket Policy Size | 20 KB | L-748707F3 | No | No | No | 
| Organizations | SCPs | Document Size | 5,120 characters | L-C48BCE79 | No | No | No |
| Organizations | RCPs | Document Size | 5,120 characters | No | No | No | No | 
| Organizations | Declarative Policies | Document Size | 10,000 characters | No | No | No | No | 
| Organizations | AI Services Opt-out Policies | Document Size | 2,500 characters | No | No | No | No | 
| Organizations | Tag Policies | Document Size | 10,000 characters | No | No | No | No | 
| Organizations | Backup Policies | Document Size | 10,000 characters | No | No | No | No | 
| Organizations | Chat Application Policies | Document Size | 10,000 characters | No | No | No | No | 
| Systems Manager | Parameter Store Standard Parameter | Size | 4 KB | L-BCC99751 | No | No | No | 
| Systems Manager | Parameter Store Advanced Parameter | Size | 8 KB | L-CECCEB04 | No | No | No | 
| Lambda | Lambda Environment Variables | Combined Size | 4 KB | L-6581F036 | No | No | No |
| Secrets Manager | Secret | Value Size | 65,536 bytes | L-2F24C883 | No | No | No |

Note: Yes* for service quota visibility means we do see some visibility.  This seems limited to resources that have been recently updated.

### IAM Managed Policies (Global)

Limit: 6,144 characters  
Note: white space doesn't count  
[AWS Documentation on IAM Limits](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).

### IAM Role Trust Policy (Global)

Limit: 2,048 characters.
Note: white space doesn't count.  This limit is adjustable up to 4,096.
[AWS Documentation on IAM Limits](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).

### IAM Managed Policies Per Role (Global)

Limit: 10 Managed Policies Per Role.
Note: There is limited support in CloudWatch and Service Quotas.

### EC2 User Data (Region Specific)

Limit: 16 KB  
Note: 16 KB is the limit for unencoded.  EC2 encodes user data.  
[EC2 User Data Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html)

### S3 Bucket Policy Size (Region Specific)

Limit: 20 KB  
Note: AWS does some normalization on bucket policies.  aws-size will approximate the normalization - the numbers may be slighty different.

### AWS Organizations Service Control Policies (Global)

Limit: 5,120 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### AWS Organizations Resource Control Policies (Global)

Limit: 5,120 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### AWS Organizations Declarative Policies (Global)

Limit: 10,000 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### AWS Organizations AI Services Opt-out Policies (Global)

Limit: 2,500 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### AWS Organizations Tag Policies (Global)

Limit: 10,000 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### AWS Organizations Backup Policies (Global)

Limit: 10,000 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### AWS Organizations Chat Application (Q) Policies (Global)

Limit: 10,000 characters  
Note: If policies are saved via CLI or SDK, white space is preserved.  This operation can be called from the management account or a member account if proper permissions are delegated.    
[Organizations Limits Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)

### Systems Manager Parameter Store Parameter (Region Specific)

Limit: 4 KB (Standard)
Limit: 8 KB (Advanced)
Note: Decryption may be necessary to determine accurate size of parameters.

### Lambda Environment Variables (Region Specific)

Limit: 4 KB 
Note: Decryption may be necessary to determine accurate size of environment variables.  The 4 KB limit is a combined limit for all variables.

### Secrets Manager Secrets (Region Specific)

Limit: 65,536 bytes
Note: To accurately determine size of secrets, `secretsmanager:GetSecretValue` and `kms:Decrypt` may be needed.  Check IAM permissions for aws-size.
