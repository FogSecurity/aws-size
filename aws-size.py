import argparse
import boto3
import questionary
import base64
import sys
import json

parser = argparse.ArgumentParser(prog='AWS Size')

parser.add_argument("--profile")
parser.add_argument("--threshold", help='Set threshold for reporting (between 0 and 1).  Default is 90%')
parser.add_argument("--region")

args = parser.parse_args()

supported_limits = [
        "AWS IAM Managed Policies",
        "AWS IAM Role Trust Policy",
        "AWS EC2 User Data",
        "Organizations SCPs",
        "Organizations RCPs",
        "AWS KMS Key Policies"
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

elif limit == 'AWS IAM Role Trust Policy':
    try:
        session = boto3.Session(profile_name = args.profile)
        iam_client = session.client('iam')

        #Hard coded Service Quota Region
        sq_client = session.client('service-quotas', region_name = 'us-east-1')
    except:
        print("Potential authentication issue: check credentials and try again")
        sys.exit()

    try:
        trust_policy_quota = sq_client.get_service_quota(
            ServiceCode='iam',
            QuotaCode='L-C07B4B0D'
        )
    except:
        print("Error retrieving Service Quota for IAM")
        sys.exit()

    try:
        iam_roles_results = [
            iam_client.get_paginator('list_roles')
            .paginate()
            .build_full_result()
        ]
    except:
        print("Issue with listing IAM roles")
        sys.exit()


    role_trust_quota = trust_policy_quota['Quota']['Value']
    roles = iam_roles_results[0]['Roles']

    warning_roles = []

    for role in roles:
        arn = role['Arn']
        name = role['RoleName']

        try:
            trust_policy = iam_client.get_role(RoleName=name)
            trust_policy = trust_policy['Role']['AssumeRolePolicyDocument']

            str_trust_policy = json.dumps(trust_policy, indent=None, separators=(', ', ':'))

            stripped_str_policy = str_trust_policy.replace(" ", "")
            char_count = len(stripped_str_policy)

            usage = round(char_count / role_trust_quota, 4)
            char_left = role_trust_quota - char_count

            if usage >= threshold:
                warning_roles.append({
                    'arn': arn,
                    'name': name,
                    'usage': usage,
                    'charleft': char_left
                })

        except:
            print(f"Issue processing role: {arn}")

    #Eventually standardize output here
    #Output Section
    print("IAM Roles Scanned: " + str(len(roles)))
    print(f"IAM Roles with Trust Policy usage over {threshold:.2%} " + str(len(warning_roles)))
    print('\n')
    print(f"List of roles with more than {threshold:.2%} trust policy length character usage: ")

    for role in warning_roles:
        print(role['arn'])
        print(f"Trust Policy Usage: {role['usage']:.2%}")
        print("Characters Left: " + str(role['charleft']) + '\n')

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
    print("EC2 Instances Scanned: " + str(len(instances)))
    print(f"EC2 Instances with usage over {threshold:.2%} " + str(len(warning_instances)))
    print('\n')
    print(f"List of instances with more than {threshold:.2%} size usage: ")

    for instance in warning_instances:
        print(instance['instance_id'])
        print(f"Instance Usage: {instance['usage']:.2%}")
        print(f"Size Left: {instance['sizeleft']} Bytes \n")

elif limit == 'Organizations SCPs' or limit == 'Organizations RCPs': 


    try:
        session = boto3.Session(profile_name = args.profile)
        organizations_client = session.client('organizations')
    except:
        print("Potential authentication issue: check credentials and try again")
        sys.exit()

    if limit == 'Organizations SCPs':
        selected_resource = "SCP"
    elif limit == 'Organizations RCPs':
        selected_resource = "RCP"

    try:

        if selected_resource == "SCP":
            org_filter = 'SERVICE_CONTROL_POLICY'
        elif selected_resource == "RCP":
            org_filter = 'RESOURCE_CONTROL_POLICY'

        organizations_results = [
            organizations_client.get_paginator('list_policies')
            .paginate(
                Filter=org_filter
            )
            .build_full_result()
        ]
    except:
        print("Issue with listing " + selected_resource + "s")
        sys.exit()

    org_policies = organizations_results[0]['Policies']
    warning_org_policies = []

    for policy in org_policies:
        try:
            policy_details = organizations_client.describe_policy(
                PolicyId=policy['Id']
            )

            policy_content = policy_details['Policy']['Content']
            policy_id = policy['Id']
            policy_name = policy['Name']

            char_count = len(policy_content)

            char_left = 5120 - char_count
            usage = round(char_count / 5120, 4)

            if usage >= threshold:
                warning_org_policies.append({
                    'policy_id': policy_id,
                    'policy_name': policy_name,
                    'usage': usage,
                    'charleft': char_left
                })

        except:
            print(f"Issue processing {selected_resource}: {policy_id}")

    #Eventually standardize output here
    #Output Section
    print(f"Organizations {selected_resource}s Scanned: " + str(len(org_policies)))
    print(f"Organizations {selected_resource}s with usage over {threshold:.2%} " + str(len(warning_org_policies)))
    print('\n')
    print(f"List of {selected_resource}s with more than {threshold:.2%} character usage: ")

    for policy in warning_org_policies:
        print(policy['policy_name'])
        print(f"{selected_resource} Usage: {policy['usage']:.2%}")
        print("Characters Left: " + str(policy['charleft']) + '\n')

elif limit == "AWS KMS Key Policies":
    try:
        session = boto3.Session(profile_name = args.profile, region_name = args.region)
        kms_client = session.client('kms')
    except:
        print("Potential authentication issue: check credentials and try again")
        sys.exit()

    try:
        kms_results = [
            kms_client.get_paginator('list_keys')
            .paginate()
            .build_full_result()
        ]
    except:
        print("Issue with listing KMS keys")
        sys.exit()
        
    keys = kms_results[0]['Keys']
    warning_keys = []

    for key in keys:
        try:
            key_arn = key['KeyArn']
            key_policy = kms_client.get_key_policy(
                KeyId=key_arn
            )

            key_policy_doc = key_policy['Policy']
        
        except:
            print(f"Issue processing key policy: {key_arn}")
            continue
        
        str_key_policy = json.dumps(key_policy_doc, indent=None, separators=(',', ':'))

        stripped_str_policy = str_key_policy.replace(" ", "")
        char_count = len(stripped_str_policy)

        print(char_count)

        #32768