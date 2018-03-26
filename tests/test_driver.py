import boto3
import logging
import os
import unittest

logging.basicConfig(
   level=logging.DEBUG,
   format='%(asctime)s:%(levelname)s:%(name)s:%(message)s'
)

logging.getLogger('boto').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


class DriverTest(unittest.TestCase):
    def setUp(self):
        self.dynamodb_client = boto3.client(
            'dynamodb',
            endpoint_url='http://localhost:4567',
            aws_access_key_id='anything',
            aws_secret_access_key='anything',
        )
        try:
            response = self.dynamodb_client.create_table(
                AttributeDefinitions=[
                    {
                        'AttributeName': 'name',
                        'AttributeType': 'S'
                    },
                ],
                TableName='gsuite-driver-state',
                KeySchema=[
                    {
                        'AttributeName': 'name',
                        'KeyType': 'HASH'
                    },
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 100,
                    'WriteCapacityUnits': 100
                }
            )
        except Exception as e:
            response = self.dynamodb_client.delete_table(
                TableName='gsuite-driver-state'
            )

            import time
            time.sleep(3)

            response = self.dynamodb_client.create_table(
                AttributeDefinitions=[
                    {
                        'AttributeName': 'name',
                        'AttributeType': 'S'
                    },
                ],
                TableName='gsuite-driver-state',
                KeySchema=[
                    {
                        'AttributeName': 'name',
                        'KeyType': 'HASH'
                    },
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 100,
                    'WriteCapacityUnits': 100
                }
            )

        response = self.dynamodb_client.describe_table(
            TableName='gsuite-driver-state'
        )

        while response['Table'].get('TableStatus') != 'ACTIVE':
            response = self.dynamodb_client.describe_table(
                TableName='gsuite-driver-state'
            )

        from gsuite_driver.driver import AuditTrail
        dynamodb = boto3.resource('dynamodb', endpoint_url='http://localhost:4567/')
        table = dynamodb.Table('gsuite-driver-state')
        audit = AuditTrail()
        audit.table = table

        fake_pre_existing_drive = {
            'name': 't_fake_pre_existing_drive',
            'id': '123456abc123',
            'kind': 'drive#teamDrive'
        }

        audit.create(fake_pre_existing_drive)

    def test_driver_init(self):
        from gsuite_driver.driver import TeamDrive

        t = TeamDrive(
            drive_name='t_fake_pre_existing_drive',
            environment='development',
            interactive_mode='False'
        )

        assert t is not None

    def test_name_is_blocked(self):
        from gsuite_driver.driver import TeamDrive

        from gsuite_driver.driver import AuditTrail
        dynamodb = boto3.resource('dynamodb', endpoint_url='http://localhost:4567/')
        table = dynamodb.Table('gsuite-driver-state')
        audit = AuditTrail()
        audit.table = table

        t = TeamDrive(
            drive_name='t_fake_pre_existing_drive',
            environment='development',
            interactive_mode='False'
        )

        t.audit = audit
        t.gsuite_api = 'fakecredz'
        blocked_check = audit.is_blocked(drive_name='t_fake_pre_existing_drive')
        assert blocked_check is True

    def tearDown(self):
        self.dynamodb_client = boto3.client(
            'dynamodb',
            endpoint_url='http://localhost:4567',
            aws_access_key_id='anything',
            aws_secret_access_key='anything',
        )

        response = self.dynamodb_client.delete_table(
            TableName='gsuite-driver-state'
        )
