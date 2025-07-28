import argparse
import boto3
import botocore
import json
import sys

parser = argparse.ArgumentParser(prog='IAM Size')

parser.add_argument("--profile")
parser.add_argument("--threshold", help='Set threshold for reporting (between 0 and 1).  Default is 90%')

args = parser.parse_args()

try:
    if args.threshold:
        if args.threshold == 'all':
            threshold = 0
        else:
            threshold = float(args.threshold)
            if threshold > 1 or threshold < 0:
                print("Threshold must be a number between 0 and 1.  Running aws-size with default of 90%")
                threshold = 0.90
            
    else:
        threshold = 0.90
except: 
    print("Threshold must be a number between 0 and 1.  Running aws-size with default of 90%")
    threshold = 0.90

try:
    session = boto3.Session(profile_name = args.profile)
    iam_client = session.client('iam')
except:
    print("Potential authentication issue: check credentials and try again")
    sys.exit()

try:
    iam_policies_results = [
        iam_client.get_paginator('list_policies')
        .paginate(Scope='Local'
        )
        .build_full_result()
    ]
except:
    print("Issue with listing IAM managed policies")
    sys.exit()

customer_managed_policies = iam_policies_results[0]['Policies']
managed_policies_stats = []
warning_policies = []

for managed_policy in customer_managed_policies:
    version = managed_policy['DefaultVersionId']
    arn = managed_policy['Arn']
    name = managed_policy['PolicyName']

    try:
        policy = iam_client.get_policy_version(
            PolicyArn=arn,
            VersionId=version
        )

        policy_doc = policy['PolicyVersion']['Document']

        str_policy = json.dumps(policy_doc, indent=None, separators=(',', ':'))

        #Strip white space
        stripped_str_policy = str_policy.replace(" ", "")
        char_count = len(stripped_str_policy)

        usage = round(char_count / 6144, 4)
        char_left = 6144 - len(stripped_str_policy)

        if usage >= threshold:
            warning_policies.append({
                'arn': arn,
                'name': name,
                'usage': usage,
                'charleft': char_left
            })
    
    except:
        print(f"Issue processing policy: {arn}")

#Output Section
print("Customer Managed Policies Scanned: " + str(len(managed_policies_stats)))
print(f"Customer Managed Policies with usage over {threshold:.2%} " + str(len(warning_policies)))
print('\n')
print(f"List of policies with more than {threshold:.2%} character usage: ")

for policy in warning_policies:
    print(policy['arn'])
    print(f"Policy Usage: {policy['usage']:.2%}")
    print("Characters Left: " + str(policy['charleft']) + '\n')
