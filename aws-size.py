import argparse
import boto3
import botocore
import json

parser = argparse.ArgumentParser(prog='AWS Size')

parser.add_argument("--profile")

args = parser.parse_args()
session = boto3.Session(profile_name = args.profile)

iam_client = session.client('iam')

iam_policies_results = [
    iam_client.get_paginator('list_policies')
    .paginate(Scope='Local'
    )
    .build_full_result()
]

customer_managed_policies = iam_policies_results[0]['Policies']
managed_policies_stats = []
warning

for managed_policy in customer_managed_policies:
    version = managed_policy['DefaultVersionId']
    arn = managed_policy['Arn']
    name = managed_policy['PolicyName']

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

    managed_policies_stats.append({
        'Arn': arn,
        'Name': name,
        'Usage': usage,
        'CharLeft': char_left
    })

print(managed_policies_stats)

    