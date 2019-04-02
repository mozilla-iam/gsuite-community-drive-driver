"""Mozilla GSuite Driver"""
import boto3
import credstash
import httplib2
import logging
import os
import time
import uuid

from apiclient import discovery
from oauth2client.service_account import ServiceAccountCredentials
from prompt_toolkit import prompt

from apiclient.errors import HttpError

try:
    from settings import get_config
    from exceptions import DriveNameLockedError
except ImportError:
    from gsuite_driver.settings import get_config
    from gsuite_driver.exceptions import DriveNameLockedError


SA_CREDENTIALS_FILENAME = "GDrive.json"
APPLICATION_NAME = "Gdrive-Community-Test"

logger = logging.getLogger(__name__)


def get_secret(secret_name, context):
    """Fetch secret from environment or credstash."""
    secret = os.getenv(secret_name.split(".")[1], None)

    if not secret:
        secret = credstash.getSecret(
            name=secret_name, context=context, region="us-west-2"
        )
    return secret


def ask_question(interactive_mode, message, operation, drive_name, detail):
    if interactive_mode == "True":
        question = prompt(
            "Allow: {} for operation: {} on drive: {}.  Detail: {}. (Y/N)".format(
                message, operation, drive_name, detail
            )
        )

        if question == "Y":
            return True
        else:
            return False

    return True


class AuditTrail(object):
    def __init__(self):
        self.boto_session = boto3.session.Session()
        self.config = get_config()
        self.table_name = self.config(
            "state_table", namespace="gsuite_driver", default="gsuite-driver-state"
        )
        self.table = None

    def connect(self):
        resource = self.boto_session.resource("dynamodb")
        self.table = resource.Table(self.table_name)
        return self.table

    def create(self, drive):
        if self.table is None:
            self.connect()

        result = self.table.put_item(Item=drive)

        return result

    def is_blocked(self, drive_name):
        if self.table is None:
            self.connect()

        result = self.table.get_item(Key={"name": drive_name})

        if result.get("Item", False):
            return True
        else:
            return False

    def populate(self, all_drive_objects):
        for drive in all_drive_objects:
            self.create(drive)

    def find(self, drive_name):
        if self.table is None:
            self.connect()

        result = self.table.get_item(Key={"name": drive_name})
        logger.info(
            "Result of the find operation is: {}".format(result),
            extra={"result": result},
        )
        return result.get("Item", False)

    def update(self, drive_name, members):
        if self.table is None:
            self.connect()

        result = self.table.get_item(Key={"name": drive_name})

        item = result.get("Item", False)

        if item is not False:
            item["members"] = members
            result = self.table.put_item(Item=item)
        else:
            result = None

        return result


class Archive(object):
    def __init__(self, master_grouplist, master_drive_list, interactive_mode):
        self.master_grouplist = master_grouplist
        self.master_drive_list = master_drive_list
        self.interactive_mode = interactive_mode

    def should_be_archived(self, drive):
        logger.debug(self.master_grouplist)
        drive_name = self.derive_group_name_from_drive(drive)
        if drive_name not in self.master_grouplist:
            logger.debug("Drive {} not in master grouplist.".format(drive_name))
            return True

    def derive_group_name_from_drive(self, drive):
        if drive.get("name").startswith("t_"):
            group_name_for_drive = drive.get("name")[-(len(drive.get("name")) - 2) :]
            group_name_for_drive = (
                "mozilliansorg_" + group_name_for_drive.split("_mozilliansorg")[0]
            )
        else:
            group_name_for_drive = (
                "mozilliansorg_" + drive.get("name").split("_mozilliansorg")[0]
            )

        return group_name_for_drive


class TeamDrive(object):
    def __init__(self, drive_name, environment, interactive_mode="True"):
        self.audit = None
        self.drive = None
        self.drive_name = drive_name
        self.drive_metadata = self._format_metadata(drive_name)
        self.environment = environment
        self.gsuite_api = None
        self.drive_list = None
        self.interactive_mode = interactive_mode
        self.whitelist = []

    def create(self):
        """Creates a new team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Creating a new team drive.",
            operation="CREATE",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        result = (
            self.gsuite_api.teamdrives()
            .create(
                body=self.drive_metadata,
                requestId=self._generate_request_id(),
                fields="id",
            )
            .execute()
        )

        time.sleep(2)
        self.find()
        logger.info("Ensuring the robot owns the drive.")
        self.ensure_iam_robot_owner()

        logger.info(
            "A new gdrive has been created for proposed name: {}".format(
                self.drive_name
            )
        )
        return result

    def destroy(self):
        """Deletes a team drive and all the files in it."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Delete a team drive.",
            operation="DESTROY",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drive = self.find()
        result = (
            self.gsuite_api.teamdrives().delete(teamDriveId=drive.get("id")).execute()
        )
        return result

    def update(self, drive_id, name):
        """Takes a drive object and makes it conform with the naming standard in addition to other things."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Run an update on a drive object.",
            operation="PUT",
            drive_name=self.drive_name,
            detail="New name for drive proposed is: {}".format(name),
        )

        if interactive_result is False:
            return None

        if self.drive_name == name:
            logger.debug("Nothing to update.  Drive name is already conformant.")
            return None

        if self.gsuite_api is None:
            self.authenticate()

        self.ensure_iam_robot_owner()

        drive_object_body = {"name": name, "kind": "drive#teamDrive"}

        result = (
            self.gsuite_api.teamdrives()
            .update(teamDriveId=drive_id, body=drive_object_body)
            .execute()
        )

        return result

    def all(self):
        """Enumerate all teamDrive objects."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="List all team drive objects.",
            operation="GET",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drives = []
        # Pull back the first page of drives
        result = (
            self.gsuite_api.teamdrives()
            .list(pageSize=100, useDomainAdminAccess=True)
            .execute()
        )

        while result.get("nextPageToken", None) is not None:
            for drive in result.get("teamDrives"):
                if self._is_governed_by_connector(drive) == True:
                    drives.append(drive)

            logger.info(
                "Drive not found in page.  Pulling next page: {}".format(
                    result.get("nextPageToken")
                )
            )

            result = (
                self.gsuite_api.teamdrives()
                .list(
                    pageSize=100,
                    pageToken=result.get("nextPageToken"),
                    useDomainAdminAccess=True,
                )
                .execute()
            )

        for drive in result.get("teamDrives"):
            if self._is_governed_by_connector(drive) == True:
                drives.append(drive)

        self.drive_list = drives
        return drives

    def archive(self, grouplist):
        """Enumerate all teamDrive objects."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Run drive archiving routine?",
            operation="FUNC",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        all_drives = self.all()
        archive = Archive(grouplist, all_drives, self.interactive_mode)
        for drive in all_drives:
            if archive.should_be_archived(drive):
                self.drive = drive
                self.drive_name = drive.get("name")
                interactive_result = ask_question(
                    interactive_mode=self.interactive_mode,
                    message="Archive this drive?",
                    operation="GET",
                    drive_name=self.drive_name,
                    detail=None,
                )

                memberships = self._membership_to_email_list(self.members)

                for member in memberships:
                    interactive_result = ask_question(
                        interactive_mode=self.interactive_mode,
                        message="Remove user for drive?",
                        operation="DEL",
                        drive_name=self.drive_name,
                        detail=member,
                    )
                    self.member_remove(member)

                if len(self.members) == 0:
                    new_name = (
                        "archived_" + str(int(time.time())) + "_" + drive.get("name")
                    )
                    interactive_result = ask_question(
                        interactive_mode=self.interactive_mode,
                        message="Move drive to archived state?",
                        operation="PUT",
                        drive_name=self.drive_name,
                        detail=new_name,
                    )
                all_drives.remove(drive)
            else:
                logger.debug(
                    "The drive: {} is still active and should not be archived.".format(
                        drive.get("name")
                    )
                )

    def _is_governed_by_connector(self, drive):
        drive_name = drive.get("name")
        if self.whitelist != []:
            if drive_name not in self.whitelist:
                return False

        if drive_name.startswith("archived") and drive_name.endswith("mozilliansorg"):
            return False

        if drive_name.startswith("prod_mozilliansorg"):
            return True

        if drive_name.startswith("dev_mozilliansorg"):
            return True

        if drive_name.startswith("t_") and drive_name.endswith("mozilliansorg"):
            return True

        if drive_name.endswith("mozilliansorg"):
            return True

        return False

    def find(self):
        """Locates a team drive based on name."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Search for a teamDrive.",
            operation="GET",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        if self.drive_list == [] or self.drive_list == None:
            drives = self.all()
        else:
            drives = self.drive_list
        logger.debug("All pages searched.  Proceeding to drive ident.")

        for drive in drives:
            if self.drive_name == drive.get("name"):
                logger.info(
                    "A drive with a matching name has been located for: {}".format(
                        self.drive_name
                    )
                )
                self.drive = drive
                return drive

        logger.info("Unable to locate drive: {}".format(self.drive_name))
        return None

    def find_or_create(self):
        """Opportunistic provisioner of team drives."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Find or create a drive.",
            operation="GET",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drive_exists = self.find()

        if drive_exists is not None:
            logger.info("Drive pre-exists for name: {}".format(self.drive_name))
            return drive_exists
        else:
            logger.info(
                "Could not locate drive proceeding to creation: {}".format(
                    self.drive_name
                )
            )
            if self.audit is None:
                self.audit = AuditTrail()
            if not self.audit.is_blocked(self.drive_name):
                self.create()
                drive = self.find()
                self.audit.create(drive)
                return drive
            else:
                raise (DriveNameLockedError)
                logger.warn(
                    "Drive name is locked.  Refusing recycle for: {}.".format(
                        self.drive_name
                    )
                )

    @property
    def members(self):
        """Return the listing of members allowed access to the team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="List all members of a teamDrive.",
            operation="GET",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drive = self.find()
        selector_fields = "permissions(kind,id,type,emailAddress,domain,role,allowFileDiscovery,displayName,photoLink,expirationTime,teamDrivePermissionDetails,deleted)"

        try:
            resp = (
                self.gsuite_api.permissions()
                .list(
                    fileId=drive.get("id"),
                    supportsTeamDrives=True,
                    useDomainAdminAccess=True,
                    fields=selector_fields,
                )
                .execute()
            )

            permissions = resp.get("permissions", [])
        except Exception as e:
            logger.error(
                "Could not get permissions from drive: {} due to: {}".format(
                    self.drive_name, e
                )
            )
            permissions = []
        return permissions

    def member_add(self, member_email):
        """Add a member to a team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Add a member with permission sets to a team drive.",
            operation="PUT",
            drive_name=self.drive_name,
            detail=member_email,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        # For now assume we only give write.
        role = "fileOrganizer"

        body = {
            "type": "user",
            "role": role,
            "emailAddress": member_email,
            "sendNotificationEmail": False,
        }

        drive = self.find()
        try:
            res = (
                self.gsuite_api.permissions()
                .create(
                    body=body,
                    fileId=drive.get("id"),
                    supportsTeamDrives=True,
                    useDomainAdminAccess=True,
                    fields="id",
                )
                .execute()
            )

        except Exception as e:
            logger.info("Could not add user {} due to : {}".format(member_email, e))
            res = e
        return res

    def ensure_iam_robot_owner(self):
        """Add a member to a team drive."""
        if self.gsuite_api is None:
            self.authenticate()
        # For now assume we only give write.

        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Add the IAM robot to the drive as owner.",
            operation="PUT",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.environment == "production":
            logger.info("prod configuration active.")
            email = "iam-robot@mozilla.com"
        elif self.environment == "development":
            logger.info("dev configuration active.")
            email = "iam-robot@test.mozilla.com"
        else:
            email = os.getenv("delegated_credentials")

        role = "organizer"
        body = {"type": "user", "role": role, "emailAddress": email}

        drive = self.find()

        try:
            result = (
                self.gsuite_api.permissions()
                .create(
                    body=body,
                    fileId=drive.get("id"),
                    supportsTeamDrives=True,
                    useDomainAdminAccess=True,
                    fields="id",
                )
                .execute()
            )
        except HttpError:
            logger.warn(
                "Could not set iam robot as owner for drive: {}".format(self.drive_name)
            )

    def member_remove(self, member_email):
        """Remove a member from a team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Remove a member from a teamDrive.",
            operation="PUT",
            drive_name=self.drive_name,
            detail=member_email,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        # Do not strip owner.
        if (
            member_email == "iam_robot@test.mozilla.com"
            or member_email == "iam_robot@mozilla.com"
        ):
            logger.info("Refusing to strip the drive owner.")
            return None

        drive = self.find()
        permission_id = self._email_to_permission_id(member_email)
        return (
            self.gsuite_api.permissions()
            .delete(
                fileId=drive.get("id"),
                permissionId=permission_id,
                supportsTeamDrives=True,
                useDomainAdminAccess=True,
            )
            .execute()
        )

    def reconcile_members(self, member_list):
        """Reconcile the list of current members with a list of emails."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message="Reason about membership.",
            operation="localhost",
            drive_name=self.drive_name,
            detail=None,
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        additions = []
        removals = []
        noops = []

        current_drive_members = self._membership_to_email_list(self.members)

        for member in member_list:
            if member in current_drive_members:
                noops.append(member.lower())
            elif member not in current_drive_members:
                additions.append(member.lower())
            else:
                pass

        audit = AuditTrail()
        current_members = additions + noops
        audit.update(self.drive_name, current_members)

        for member in current_drive_members:
            if member not in member_list:
                removals.append(member.lower())

        proposal = {"additions": additions, "removals": removals, "noops": noops}
        logger.info("Membership list built: {}".format(proposal))
        return proposal

    def execute_proposal(self, reconciled_dictionary):
        """Carries out the addition, deletions, and noops."""
        if reconciled_dictionary["additions"] is not []:
            interactive_result = ask_question(
                interactive_mode=self.interactive_mode,
                message="Add all new members to the drive.",
                operation="LOCAL",
                drive_name=self.drive_name,
                detail=reconciled_dictionary["additions"],
            )

            if interactive_result is False:
                pass
            else:
                for member in reconciled_dictionary["additions"]:
                    member = member.lower()
                    logger.info(
                        "Adding member {} to {}.".format(member, self.drive_name)
                    )
                    try:
                        self.member_add(member)
                    except Exception as e:
                        logger.error(e)
                        logger.error(
                            "Could not add member {} to {}.".format(
                                member, self.drive_name
                            ),
                            extra={"reason": e, "member": member},
                        )
                        reconciled_dictionary["additions"].pop()

        if reconciled_dictionary["removals"] is not []:
            interactive_result = ask_question(
                interactive_mode=self.interactive_mode,
                message="Remove batch of members from the drive.",
                operation="LOCAL",
                drive_name=self.drive_name,
                detail=reconciled_dictionary["removals"],
            )

            if interactive_result is False:
                pass
            else:
                for member in reconciled_dictionary["removals"]:
                    member = member.lower()
                    logger.info(
                        "Removing member {} from {}.".format(member, self.drive_name)
                    )
                    try:
                        self.member_remove(member)
                    except Exception as e:
                        logger.error(e)
                        logger.info(
                            "Could not remove member {} from {}.".format(
                                member, self.drive_name
                            )
                        )
                        reconciled_dictionary["removals"].pop()

    def _email_to_permission_id(self, email):
        for member in self.members:
            if email == member.get("emailAddress"):
                return member.get("id")

    def _membership_to_email_list(self, members):
        emails = []

        if members is not None:
            for member in members:
                email = member.get("emailAddress")
                if email is not None:
                    emails.append(email.lower())
        return emails

    def authenticate(self):
        credentials = self._get_credentials()
        http = credentials.authorize(httplib2.Http())
        self.gsuite_api = discovery.build("drive", "v3", http=http)
        logger.info(
            "Authenticated with GSuite using service account: {}".format(credentials)
        )

    def _name_conformance(self, drive_name):
        if drive_name.startswith("prod_mozilliansorg") or drive_name.startswith(
            "dev_mozilliansorg"
        ):
            if self.environment == "development":
                group_name = drive_name.split("dev_mozilliansorg_")[1]
                publisher_name = (
                    "mozilliansorg"
                )  # XXX TBD some day support multiple publisher conformance
                new_name = "t_{}_{}".format(group_name, publisher_name)
            else:
                group_name = drive_name.split("prod_mozilliansorg_")[1]
                publisher_name = (
                    "mozilliansorg"
                )  # XXX TBD some day support multiple publisher conformance
                new_name = "{}_{}".format(group_name, publisher_name)
            return new_name
        else:
            return drive_name

    def _format_metadata(self, drive_name):
        return {"name": drive_name}

    def _get_credentials(self):
        """ Gets valid user credentials from stored file."""
        secret = get_secret("gsuite-driver.token", {"app": "gsuite-driver"})
        secret_file = open("/tmp/{}".format(SA_CREDENTIALS_FILENAME), "w")
        secret_file.write(secret)
        secret_file.close()
        cred_dir = os.path.expanduser("/tmp/")
        credential_path = os.path.join(cred_dir, SA_CREDENTIALS_FILENAME)

        # This scope is basically drive admin.  There is no granualar scope
        # to facilitate team drive interaction.
        scopes = ["https://www.googleapis.com/auth/drive"]

        credentials = ServiceAccountCredentials.from_json_keyfile_name(
            credential_path, scopes
        )

        if self.environment == "production":
            logger.info("prod configuration active.")
            delegated_credentials = credentials.create_delegated(
                "iam-robot@mozilla.com"
            )
        elif self.environment == "development":
            logger.info("dev configuration active.")
            delegated_credentials = credentials.create_delegated(
                "iam-robot@test.mozilla.com"
            )
        else:
            delegated_credentials = credentials.create_delegated(
                os.getenv("delegated_credentials")
            )
        return delegated_credentials

    def _generate_request_id(self):
        return str(uuid.uuid4())
