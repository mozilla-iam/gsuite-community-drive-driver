import boto3
import logging
import random

from faker import Faker

logger = logging.getLogger(__name__)


logging.getLogger("boto").setLevel(logging.CRITICAL)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)


class FakeUser(object):
    def __init__(self):
        self.fake = Faker()
        self.slugs = []

    @property
    def profile(self):
        active = [
            True,
            False,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        ]

        profile = {
            "user_id": self.user_id(),
            "firstName": self.firstName(),
            "lastName": self.lastName(),
            "groups": self.groups(),
            "primaryEmail": self.primary_email(),
            "emails": self.additional_emails(),
            "active": random.choice(active),
        }

        return profile

    def user_id(self):
        providers = ["ad|Mozilla-LDAP|", "github|", "google-oauth2|", "email|"]
        user_id = "{}{}".format(random.choice(providers), self.fake.user_name())
        return user_id

    def firstName(self):
        return self.fake.first_name_female()

    def lastName(self):
        return self.fake.last_name_female()

    def primary_email(self):
        email = "{}@{}".format(self.fake.user_name(), self._random_email_suffix())
        return email

    def additional_emails(self):
        number_of_emails = random.randint(1, 5)

        emails = []
        primary_opts = [
            True,
            False,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        ]

        for x in range(number_of_emails):
            emails.append(
                {
                    "name": self._random_provider(),
                    "primary": random.choice(primary_opts),
                    "value": self.primary_email(),
                    "verified": True,
                }
            )

        return emails

    def _random_provider(self):
        providers = [
            "LDAP Provider",
            "Github Provider",
            "Google Provider",
            "Google Provider",
            "Google Provider",
            "Google Provider",
        ]

        return random.choice(providers)

    def groups(self):
        group_opts = [0, 1, 1, 1, 1, 1, 1]
        number_of_groups = random.randint(10, 15)
        groups = []
        for x in range(number_of_groups):
            if random.choice(group_opts) == 0:
                continue
            group_name = self._random_group_name()
            if group_name not in groups:
                groups.append("{}".format(group_name))
        return groups

    def _random_group_name(self):
        if self.slugs == []:
            for x in range(random.randint(1, 50)):
                self.slugs.append(
                    self._random_publisher_prefix() + "_" + self.fake.slug()
                )
        else:
            pass

        return random.choice(self.slugs)

    def _random_email_suffix(self):
        suffixes = [
            "mozilla.com",
            "mozilla.com",
            "mozilla.com",
            "mozilla.com",
            "mozillafoundation.org",
            "gmail.com",
            "notagsuitedomain.com",
        ]

        return random.choice(suffixes)

    def _random_publisher_prefix(self):
        prefixes = [
            "hris",
            "HRIS",
            "mozilliansorg",
            "mozilliansorg",
            "mozilliansorg",
            "mozilliansorg",
            "mozilliansorg",
            "mozillians.org",
            "NOTAVALIDPREFIX",
        ]

        return random.choice(prefixes)


class FakeVault(object):
    def __init__(self):
        self.dynamodb_client = boto3.client(
            "dynamodb",
            endpoint_url="http://localhost:4567",
            aws_access_key_id="anything",
            aws_secret_access_key="anything",
        )

    def create(self):
        response = self.dynamodb_client.create_table(
            AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
            TableName="fake-identity-vault",
            KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
            ProvisionedThroughput={"ReadCapacityUnits": 100, "WriteCapacityUnits": 100},
        )

        return response

    def delete(self):
        response = self.dynamodb_client.delete_table(TableName="fake-identity-vault")

        return response

    def is_ready(self):
        response = self.dynamodb_client.describe_table(TableName="fake-identity-vault")

        if response["Table"].get("TableStatus") == "ACTIVE":
            return True
        else:
            return False

    def fake_table(self):
        dynamodb = boto3.resource("dynamodb", endpoint_url="http://localhost:4567/")
        table = dynamodb.Table("fake-identity-vault")

        return table

    def _add_record(self, record):
        table = self.fake_table()
        response = table.put_item(Item=record)

        return response

    def populate(self):
        number_of_fake_users = 1000
        logger.info(
            "Populating fake identity vault with: {} users.".format(
                number_of_fake_users
            )
        )
        fake_user = FakeUser()
        for x in range(number_of_fake_users):
            profile = fake_user.profile
            self._add_record(profile)
