#Python Script to get Secret from Amazon Secrets Manager
#Script will pull down current password; hash it and replace it in Puppet Module

import boto3
import crypt
import sys
import fileinput

from botocore.exceptions import ClientError




def get_secret():
    global secret
    secret_name = "root-pw-linux"
    endpoint_url = "https://secretsmanager.us-east-2.amazonaws.com"
    region_name = "us-east-2"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
    else:
        # Decrypted secret using the associated KMS CMK
        # Depending on whether the secret was a string or binary, one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']
        
        pw = secret.split('"')[3] 
        pwhash = crypt.crypt(pw)
#       print pwhash
        puppethash =  "password =>" +  "'" + pwhash + "'"
        print puppethash     

#Find Lines with 'password =>' and replace it with new generated line


#for line in fileinput.input(["init.pp"], inplace=True):
#    if line.strip().startswith('password =>'):
#        line = puppethash
#        outfile.write(line)



get_secret() 
 
