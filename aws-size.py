import argparse
import boto3
import questionary
import sys
import json
import base64

parser = argparse.ArgumentParser(prog='AWS Size')

parser.add_argument("--profile")
parser.add_argument("--threshold", help='Set threshold for reporting (between 0 and 1).  Default is 90%')
parser.add_argument("--region")

args = parser.parse_args()

supported_limits = [
        "AWS IAM Managed Policies",
        "AWS EC2 User Data"
]

limit = questionary.select(
    "Select a resource limit",
    choices=supported_limits,
).ask()

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

if limit == 'AWS IAM Managed Policies':

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

    #Eventually standardize output here
    #Output Section
    print("Customer Managed Policies Scanned: " + str(len(managed_policies_stats)))
    print(f"Customer Managed Policies with usage over {threshold:.2%} " + str(len(warning_policies)))
    print('\n')
    print(f"List of policies with more than {threshold:.2%} character usage: ")

    
    for policy in warning_policies:
        print(policy['arn'])
        print(f"Policy Usage: {policy['usage']:.2%}")
        print("Characters Left: " + str(policy['charleft']) + '\n')

elif limit == "AWS EC2 User Data":
    try:
        session = boto3.Session(profile_name = args.profile, region_name = args.region)
        ec2_client = session.client('ec2')
    except:
        print("Potential authentication issue: check credentials and try again")
        sys.exit()

    try:
        ec2_results = [
            ec2_client.get_paginator('describe_instances')
            .paginate()
            .build_full_result()
        ]
    except:
        print("Issue with listing EC2 instances")
        sys.exit()

    instances = ec2_results[0]['Reservations']

    ec2_stats = []
    warning_instances = []

    for reservation in instances:
        for instance in reservation['Instances']:
            try:
                instance_id = instance['InstanceId']
                user_data = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )

                if user_data.get('UserData').get('Value'):
                    user_data = user_data['UserData']['Value']

                    decoded_user_data_bytes = base64.b64decode(user_data)
                    decoded_user_data = decoded_user_data_bytes.decode('utf-8')

                    char_count = len(decoded_user_data)
                else:
                    char_count = 0

                char_left = 16384 - char_count
                usage = round(char_count / 16384, 4)

                if usage >= threshold:
                    warning_instances.append({
                        'instance_id': instance_id,
                        'usage': usage,
                        'sizeleft': char_left
                    })

            except:
                print(f"Issue processing instance: {instance_id}")

    #Eventually standardize output here
    #Output Section
    print("EC2 Instances Scanned: " + str(len(ec2_stats)))
    print(f"EC2 Instances with usage over {threshold:.2%} " + str(len(warning_instances)))
    print('\n')
    print(f"List of instances with more than {threshold:.2%} size usage: ")

    for instance in warning_instances:
        print(instance['instance_id'])
        print(f"Instance Usage: {instance['usage']:.2%}")
        print(f"Size Left: {instance['sizeleft']} Bytes \n")
