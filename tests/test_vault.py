import boto3
import logging
import os
import unittest


from fake_cis import FakeVault

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s"
)

logging.getLogger("boto").setLevel(logging.CRITICAL)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


class VaultTest(unittest.TestCase):
    def setUp(self):
        v = FakeVault()
        v.create()

        while v.is_ready() is not True:
            pass

        v.populate()

    def test_person_object(self):
        from gsuite_driver import vault
        from gsuite_driver import settings

        table_name = "fake-identity-vault"

        fake_dynamo = boto3.resource("dynamodb", endpoint_url="http://localhost:4567")
        fake_table = fake_dynamo.Table(table_name)

        cis_table = vault.CISTable(table_name)
        cis_table.table = fake_table

        config = settings.get_config()

        os.environ["CIS_DYNAMODB_PERSON_TABLE"] = "fake-identity-vault"

        os.environ["GSUITE_DRIVER_PREFIX"] = "mozilliansorg"
        p = vault.People()
        p.table = cis_table

        grouplist = p.grouplist(
            filter_prefix=config("prefix", namespace="gsuite_driver", default="mozilliansorg")
        )

        for group in grouplist:
            assert group.get("group").split("_")[0] == "mozilliansorg"

        assert len(grouplist) >= 1
        logger.info(
            "Group list built for : {} number of groups matching prefix.".format(
                len(grouplist)
            )
        )

        good_groups = 0

        for group in grouplist:
            email_list = p.build_email_list(group)
            assert email_list is not None
            good_groups = good_groups + 1

        logger.info(
            "The number of groups with valid members was: {}".format(good_groups)
        )
        assert good_groups > 0

    def tearDown(self):
        v = FakeVault()
        v.delete()
