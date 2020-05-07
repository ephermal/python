# Script to get secrets from secret manager
# Some arguments are required others are optional

import argparse
import boto3
import base64
from botocore.exceptions import ClientError, ParamValidationError
iam_client = boto3.client('iam')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--profile",
                        help="Choose the profile from aws config file ",
                        nargs='?', const="default", type=str, required=True)
    parser.add_argument("-r", "--region",
                        help="Please specify region ",
                        nargs='?', const="us-west-2", type=str, required=True)
    parser.add_argument("-s", "--secret",
                        help="Please specify secret name ",
                        nargs='?', type=str, required=True)
    args = parser.parse_args()
    region = args.region
    profile = args.profile
    secret = args.secret
    try:
        get_secret(secret, region, profile)
    except ParamValidationError as e:
        print("you need to use the proper arguments i.e python3 rotateKeys3.py\
               -u username@salesforce.com -p profile ")
        return e


def get_secret(secret, region, profile):
    secret_name = secret
    session = boto3.session.Session(profile_name=profile)
    client = session.client(
        service_name='secretsmanager',
        region_name=region,
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text
            # using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current
            # state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one
        # of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(
                get_secret_value_response['SecretBinary'])
        print(secret)


if __name__ == "__main__":
    main()
