import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _sts_client(target_account_id):
    logger.info('[START] _sts_client')
    sts_connection = boto3.client('sts')
    try:
        # Assume Role
        role_arn = "arn:aws:iam::%s:role/aws-controltower-AdministratorExecutionRole" % target_account_id
        role_session_name = "CROSS_ACCOUNT_ACCESS_FROM_CTAUDIT"
        logger.info("- RoleArn=%s" % role_arn)
        logger.info("- RoleSessionName=%s" % role_session_name)
        target = sts_connection.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
        )
    except Exception as e:
        logger.error(e)
        exit()
    else:
        client = boto3.client(
            'sts',
            aws_access_key_id=target['Credentials']['AccessKeyId'],
            aws_secret_access_key=target['Credentials']['SecretAccessKey'],
            aws_session_token=target['Credentials']['SessionToken']
        )
        logger.info('[END] _sts_client')
        return client


def check(sts_client):
    logger.info('[START] check')
    try:
        resp = sts_client.get_caller_identity()
        logger.info("- Account=%s" % resp['Account'])
        logger.info("- Arn=%s" % resp['Arn'])
    except Exception as e:
        logger.error(e)
        exit()
    else:
        logger.info('[END] check')
        return {"status": "success"}


def lambda_handler(event, context):
    logger.info('[START] lambda_handler')
    # Get Client
    sts_client = _sts_client(event['TargetAccountId'])
    # Run remediation(check)
    logger.info('# running check')
    results = check(sts_client)
    # End
    logger.info('[END] lambda_handler')
    return results
