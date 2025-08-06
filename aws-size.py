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
        "S3 Bucket Policy",
        "Organizations SCPs",
        "Organizations RCPs",
        "Organizations Declarative Policies",
        "Organizations AI Services Opt-Out Policies",
        "Organizations Tag Policies",
        "Organizations Backup Policies",
        "Organizations Chat Applications Policies",
        "SSM Parameter Store Parameters"
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

    if len(warning_policies) > 0:
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

    if len(warning_roles) > 0:
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

    if len(warning_instances) > 0:
        print(f"List of instances with more than {threshold:.2%} size usage: ")

        for instance in warning_instances:
            print(instance['instance_id'])
            print(f"Instance Usage: {instance['usage']:.2%}")
            print(f"Size Left: {instance['sizeleft']} Bytes \n")

elif limit == "S3 Bucket Policy":
    try:
        session = boto3.Session(profile_name = args.profile, region_name = args.region)
        s3_client = session.client('s3')
    except:
        print("Potential authentication issue: check credentials and try again")
        sys.exit()

    try:
        s3_buckets_results = [
            s3_client.get_paginator('list_buckets')
            .paginate()
            .build_full_result()
        ]
    except:
        print("Issue with listing S3 buckets")
        sys.exit()

    buckets = s3_buckets_results[0]['Buckets']
    warning_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']

        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_document = json.loads(bucket_policy['Policy'])

            str_policy = json.dumps(policy_document, indent=None, separators=(',', ':'))

            stripped_str_policy = str_policy.replace(" ", "")
            char_count = len(stripped_str_policy)

            # Approximate normalization for S3 bucket policy (0.8720 factor)
            usage = round(char_count / 20480 * 0.8720, 4)  # 20 KB limit for S3 bucket policy
            char_left = 20480 - (usage * 20480)

            if usage >= threshold:
                warning_buckets.append({
                    'bucket_name': bucket_name,
                    'usage': usage,
                    'charleft': char_left
                })

        except Exception as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                #print(f"No policy found for bucket: {bucket_name}")
                
                if 0 >= threshold:
                    warning_buckets.append({
                        'bucket_name': bucket_name,
                        'usage': 0,
                        'charleft': 20480
                    })
            
            else:
                print(f"Issue processing bucket: {bucket_name} - {str(e)}")
        
    print("S3 Buckets Scanned: " + str(len(buckets)))
    print(f"S3 Buckets with policy usage over {threshold:.2%} " + str(len(warning_buckets)))
    print('\n')

    if len(warning_buckets) > 0:
        print(f"List of buckets with more than {threshold:.2%} policy bytes usage: ")

        for bucket in warning_buckets:
            print(bucket['bucket_name'])
            print(f"Bucket Policy Usage: {bucket['usage']:.2%}")
            print("Bytes Left: " + str(bucket['charleft']) + '\n')


elif (limit == 'Organizations SCPs' or
    limit == 'Organizations RCPs' or
    limit == 'Organizations Declarative Policies' or
    limit == 'Organizations AI Services Opt-Out Policies' or
    limit == 'Organizations Tag Policies' or
    limit == 'Organizations Backup Policies' or
    limit == 'Organizations Chat Applications Policies' 
    ):
    
    try:
        session = boto3.Session(profile_name = args.profile)
        organizations_client = session.client('organizations')
    except:
        print("Potential authentication issue: check credentials and try again")
        sys.exit()

    if limit == 'Organizations SCPs':
        selected_resource = "SCP"
        size_limit = 5120
    elif limit == 'Organizations RCPs':
        selected_resource = "RCP"
        size_limit = 5120
    elif limit == "Organizations Declarative Policies":
        selected_resource = "Declarative Policy"
        size_limit = 10000
    elif limit == "Organizations AI Services Opt-Out Policies":
        selected_resource = "AI Services Opt-Out Policy"
        size_limit = 2500
    elif limit == "Organizations Tag Policies":
        selected_resource = "Tag Policy"
        size_limit = 10000
    elif limit == "Organizations Backup Policies":
        selected_resource = "Backup Policy"
        size_limit = 10000
    elif limit == "Organizations Chat Applications Policies":
        selected_resource = "Chat Application Policy"
        size_limit = 10000

    try:

        if selected_resource == "SCP":
            org_filter = 'SERVICE_CONTROL_POLICY'
        elif selected_resource == "RCP":
            org_filter = 'RESOURCE_CONTROL_POLICY'
        elif selected_resource == "Declarative Policy":
            org_filter = 'DECLARATIVE_POLICY_EC2'
        elif selected_resource == "AI Services Opt-Out Policy":
            org_filter = 'AISERVICES_OPT_OUT_POLICY'
        elif selected_resource == "Tag Policy":
            org_filter = 'TAG_POLICY'
        elif selected_resource == "Backup Policy":
            org_filter = 'BACKUP_POLICY'
        elif selected_resource == "Chat Application Policy":
            org_filter = 'CHATBOT_POLICY'

        organizations_results = [
            organizations_client.get_paginator('list_policies')
            .paginate(
                Filter=org_filter
            )
            .build_full_result()
        ]
    except:
        print("Issue with listing " + selected_resource)
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

            #Policy will automatically remove whitespace if saved via console.  Whitespace is not removed if saved via CLI/API.
            char_count = len(policy_content)

            char_left = size_limit - char_count
            usage = round(char_count / size_limit, 4)

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
    print(f"Organizations {selected_resource} resources scanned: " + str(len(org_policies)))
    print(f"Organizations {selected_resource} resources with usage over {threshold:.2%} " + str(len(warning_org_policies)))
    print('\n')

    if len(warning_org_policies) > 0:
        print(f"{selected_resource} resources with more than {threshold:.2%} character usage: ")

        for policy in warning_org_policies:
            print(policy['policy_name'])
            print(f"{selected_resource} Usage: {policy['usage']:.2%}")
<<<<<<< HEAD
            print("Characters Left: " + str(policy['charleft']) + '\n')
    
elif limit == 'SSM Parameter Store Parameters':
    try:
        session = boto3.Session(profile_name = args.profile, region_name = args.region)
        ssm_client = session.client('ssm')
    except:
        print("Potential authentication issue: check credentials and try again")
        sys.exit()

    try:
        ssm_results = [
            ssm_client.get_paginator('describe_parameters')
            .paginate()
            .build_full_result()
        ]
    except:
        print("Issue with listing SSM parameters")
        sys.exit()

    ssm_parameters = ssm_results[0]['Parameters']
    warning_ssm_parameters = []

    for parameter in ssm_parameters:
        try:
            parameter_name = parameter['Name']
            parameter_tier = parameter['Tier']
            parameter_arn = parameter['ARN']

            parameter_value = ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )

            if parameter_tier == 'Standard':
                param_size = 4906
            elif parameter_tier == 'Advanced':
                param_size = 8192

            char_count = len(parameter_value['Parameter']['Value'])

            char_left = param_size - char_count
            usage = round(char_count / param_size, 4)

            if usage >= threshold:
                warning_ssm_parameters.append({
                    'parameter_name': parameter_name,
                    'usage': usage,
                    'charleft': char_left
                })

        except:
            print(f"Issue processing SSM parameter: {parameter_name}")

    #Eventually standardize output here
    #Output Section
    print("SSM Parameters Scanned: " + str(len(ssm_parameters)))
    print(f"SSM Parameters with usage over {threshold:.2%} " + str(len(warning_ssm_parameters)))
    print('\n')

    if len(warning_ssm_parameters) > 0:
        print(f"List of SSM parameters with more than {threshold:.2%} character usage: ")

        for parameter in warning_ssm_parameters:
            print(parameter['parameter_name'])
            print(f"Parameter Usage: {parameter['usage']:.2%}")
            print("Characters Left: " + str(parameter['charleft']) + '\n')