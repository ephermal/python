#Script to rotate keys for aws
#Some arguments are required others are option
#Version 1 : Create, Delete, Rotate Keys - Working
#Version 2 : Edit aws credentials file (work in progress)

import argparse
import boto3
import fileinput
import sys
from botocore.exceptions import ClientError, ParamValidationError
from boto3 import Session


iam_client = boto3.client('iam')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="An IAM username, e.g. key_rotator.py --username <username>", required=True)
    parser.add_argument("-k", "--key", help="An AWS access key, e.g. key_rotator.py --key <access_key>")
    parser.add_argument("--delete", help="Deletes an access key", action="store_true")
    parser.add_argument("-s", "--show", help="Shows Current Keys", action="store_true")
    parser.add_argument("-r", "--rotate", help="rotates current key",action="store_true")
    parser.add_argument("-p", "--profile", help="Choose the profile from aws config file ", nargs='?', const="default", type=str, required=True)
    args = parser.parse_args()
    username = args.username
    profile = args.profile
    aws_profile = boto3.session.Session(profile_name=profile)
    aws_access_key = get_key(username,aws_profile)
    try:
        keys = iam_client.list_access_keys(UserName=username)
        inactive_keys = 0
        active_keys = 0
        for key in keys['AccessKeyMetadata']:
            if key['Status']=='Inactive': inactive_keys = inactive_keys + 1
            elif key['Status']=='Active': active_keys = active_keys + 1
        if args.delete:
            delete_key(aws_access_key, username,aws_profile)
        elif args.show:
            get_key(username,profile)
        elif args.rotate:
            rotate_key(username,aws_profile)
        else:
            create_key(username,aws_access_key,aws_profile)
    except ClientError as e:
        print(("The user with the name %s cannot be found." % username))
    except ParamValidationError as e:
        print ("you need to use the proper arguments i.e python3 rotateKeys3.py --username username@salesforce.com -p profile ")
    return (username, profile,aws_access_key)

def get_key(username,aws_profile):
        session = aws_profile
        credentials = session.get_credentials()
        current_credentials = credentials.get_frozen_credentials()
        return  current_credentials.access_key

def create_key(username,aws_access_key,aws_profile):
    keys = iam_client.list_access_keys(UserName=username)
    inactive_keys = 0
    active_keys = 0
    for key in keys['AccessKeyMetadata']:
        if key['Status']=='Inactive': inactive_keys = inactive_keys + 1
        elif key['Status']=='Active': active_keys = active_keys + 1
    if inactive_keys + active_keys >= 2:
        print(("%s already has 1 keys. As a best practice you are only allowed one key.") % username)
        print(("%s is your key to refresh your memory ") % aws_access_key )
        exit()
    aws_access_key = get_key(username,aws_profile)
    access_key_metadata = iam_client.create_access_key(UserName=username)['AccessKey']
    access_key = access_key_metadata['AccessKeyId']
    secret_key = access_key_metadata['SecretAccessKey']
    print(("your new access key is %s and your new secret key is %s") % (access_key, secret_key))
    access_key = ''
    secret_key = ''
    return access_key, secret_key

def delete_key(access_key,username,aws_profile):
    i = ""
    access_key = get_key(username,aws_profile)
    try:
        while i != 'y' or 'n':
            i = input("Do you want to delete the access key " + " " + access_key + " y/n" +" " )
            if i == 'y':
                iam_client.delete_access_key(UserName=username, AccessKeyId=access_key)
                print((access_key + " has been deleted."))
                return old_access_key
            elif i == 'n':
                exit()
    except ClientError as e:
        print(("The access key with id %s cannot be found" % access_key))

def rotate_key(username,aws_profile):
    aws_access_key = get_key(username,aws_profile)
    print ("Removing Old Key")
    delete_key(aws_access_key,username,aws_profile)
    print ("creating new key")
    create_key(username,aws_access_key,aws_profile)

if __name__ == "__main__":
    main()
