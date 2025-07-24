import argparse
import boto3
import botocore
import json

parser = argparse.ArgumentParser(prog='AWS Size')

parser.add_argument("--profile")

args = parser.parse_args()
#list-policies

#For reach policy, get size
    #Get Policy 
    #Get Policy Version

session = boto3.Session(profile_name = args.profile)

iam_client = session.client('iam')

iam_policies_results = [
    iam_client.get_paginator('list_policies')
    .paginate()
    .build_full_result()
]

print(iam_policies_results)