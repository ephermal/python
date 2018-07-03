import boto3
import crypt
import string
import random
from botocore.exceptions import ClientError

# Global Variables
secret_name = "root-pw-linux"
endpoint_url = "https://secretsmanager.us-east-2.amazonaws.com"
region_name = "us-east-2"

# defines new password characteristics
password_charset = string.ascii_lowercase + string.digits + string.punctuation


# defines new password randomly generated


def new_password(char_set, length):
    if not hasattr(new_password, "rng"):
        new_password.rng = random.SystemRandom()  # Create a static variable
    return ''.join([new_password.rng.choice(char_set) for _ in xrange(length)])


# Updats it to Amazon
def update_secret():
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )
    password = new_password(password_charset, 16)
    client.update_secret(SecretId=secret_name, SecretString=password)


# Get Secret from Amazon
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

        # pw = secret.split('"')[3]
        print secret
        pwhash = crypt.crypt(secret)
        print "'" + pwhash + "'"


update_secret()
get_secret()
