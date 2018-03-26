"""Mozilla GSuite Driver"""
import credstash
import httplib2
import logging
import os
import uuid

from apiclient import discovery
from oauth2client.service_account import ServiceAccountCredentials
from prompt_toolkit import prompt

SA_CREDENTIALS_FILENAME = 'GDrive.json'
APPLICATION_NAME = 'Gdrive-Community-Test'

logger = logging.getLogger(__name__)


def get_secret(secret_name, context):
    """Fetch secret from environment or credstash."""
    secret = os.getenv(secret_name.split('.')[1], None)

    if not secret:
        secret = credstash.getSecret(
            name=secret_name,
            context=context,
            region="us-west-2"
        )
    return secret


def ask_question(interactive_mode, message, operation, drive_name, detail):
    if interactive_mode == 'True':
        question = prompt(
            'Allow: {} for operation: {} on drive: {}.  Detail: {}. (Y/N)'.format(
                message,
                operation,
                drive_name,
                detail
            )
        )

        if question == 'Y':
            return True
        else:
            return False

    return True


class TeamDrive(object):
    def __init__(self, drive_name, environment, state_table=None, interactive_mode='True'):
        self.drive = None
        self.drive_name = drive_name
        self.drive_metadata = self._format_metadata(drive_name)
        self.environment = environment
        self.state_table = None
        self.gsuite_api = None
        self.drive_list = None
        self.interactive_mode = interactive_mode
        self.whitelist = []

    def create(self):
        """Creates a new team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Creating a new team drive.',
            operation='CREATE',
            drive_name=self.drive_name,
            detail=None
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        result = self.gsuite_api.teamdrives().create(
                body=self.drive_metadata,
                requestId=self._generate_request_id(),
                fields='id'
        ).execute()

        self.find()

        logger.info("Ensuring the robot owns the drive.")
        self.ensure_iam_robot_owner()

        logger.info('A new gdrive has been created for proposed name: {}'.format(self.drive_name))

        return result

    def destroy(self):
        """Deletes a team drive and all the files in it."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Delete a team drive.',
            operation='DESTROY',
            drive_name=self.drive_name,
            detail=None
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drive = self.find()
        result = self.gsuite_api.teamdrives().delete(teamDriveId=drive.get('id')).execute()
        return result

    def update(self, drive_id, name):
        """Takes a drive object and makes it conform with the naming standard in addition to other things."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Run an update on a drive object.',
            operation='PUT',
            drive_name=self.drive_name,
            detail='New name for drive proposed is: {}'.format(name)
        )

        if interactive_result is False:
            return None

        if self.drive_name == name:
            logger.debug('Nothing to update.  Drive name is already conformant.')
            return None

        if self.gsuite_api is None:
            self.authenticate()

        self.ensure_iam_robot_owner()

        drive_object_body = {
          'name': name,
          'kind': 'drive#teamDrive'
        }

        result = self.gsuite_api.teamdrives().update(
                teamDriveId=drive_id,
                body=drive_object_body
        ).execute()

        return result

    def all(self):
        """Enumerate all teamDrive objects."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='List all team drive objects.',
            operation='GET',
            drive_name=self.drive_name,
            detail=None
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drives = []
        # Pull back the first page of drives
        result = self.gsuite_api.teamdrives().list(pageSize=100, useDomainAdminAccess=True).execute()

        while result.get('nextPageToken', None) is not None:
            for drive in result.get('teamDrives'):
                drives.append(drive)

            logger.info('Drive not found in page.  Pulling next page: {}'.format(result.get('nextPageToken')))

            result = self.gsuite_api.teamdrives().list(
                pageSize=100, pageToken=result.get('nextPageToken'), useDomainAdminAccess=True
            ).execute()

        for drive in result.get('teamDrives'):
            if self._is_governed_by_connector(drive):
                drives.append(drive)

        self.drive_list = drives
        print(self.drive_list)
        return drives

    def _is_governed_by_connector(self, drive):
        drive_name = drive.get('name')
        if self.whitelist != []:
            if drive_name not in self.whitelist:
                return False

        if drive_name.startswith('prod_mozilliansorg'):
            return True

        if drive_name.startswith('dev_mozilliansorg'):
            return True

        if drive_name.endswith('mozilliansorg'):
            return True

        return False

    def find(self):
        """Locates a team drive based on name."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Search for a teamDrive.',
            operation='GET',
            drive_name=self.drive_name,
            detail=None
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        if self.drive is not None:
            logger.info('Drive already has been discovered returning self.drive: {}'.format(self.drive_name))
            return self.drive
        else:
            if self.drive_list is None:
                drives = self.all()
            else:
                drives = self.drive_list

            logger.info('All pages searched.  Proceeding to drive ident.')

            for drive in drives:
                if self.drive_name == drive.get('name'):
                    logger.info('A drive with a matching name has been located for: {}'.format(self.drive_name))
                    self.drive = drive
                    return drive

            logger.info('Unable to locate drive: {}'.format(self.drive_name))
        return None

    def find_or_create(self):
        """Opportunistic provisioner of team drives."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Find or create a drive.',
            operation='GET',
            drive_name=self.drive_name,
            detail=None
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drive_exists = self.find()

        if drive_exists is not None:
            logger.info('Drive pre-exists for name: {}'.format(self.drive_name))
            return drive_exists
        else:
            logger.info('Could not locate drive proceeding to creation: {}'.format(self.drive_name))
            self.create()
            return self.find()

    @property
    def members(self):
        """Return the listing of members allowed access to the team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='List all members of a teamDrive.',
            operation='GET',
            drive_name=self.drive_name,
            detail=None
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        drive = self.find()
        selector_fields = "permissions(kind,id,type,emailAddress,domain,role,allowFileDiscovery,\
            displayName,photoLink,expirationTime,teamDrivePermissionDetails,deleted)"

        resp = self.gsuite_api.permissions().list(
            fileId=drive.get('id'), supportsTeamDrives=True,
            useDomainAdminAccess=True, fields=selector_fields
        ).execute()

        permissions = resp.get('permissions')
        return permissions

    def member_add(self, member_email):
        """Add a member to a team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Add a member with permission sets to a team drive.',
            operation='PUT',
            drive_name=self.drive_name,
            detail=member_email
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()
        # For now assume we only give write.
        role = 'organizer'

        body = {
            'type': 'user', 'role': role,
            'emailAddress': member_email, 'sendNotificationEmail': False
        }

        drive = self.find()
        try:
            res = self.gsuite_api.permissions().create(
                body=body, fileId=drive.get('id'),
                supportsTeamDrives=True,
                useDomainAdminAccess=True,
                fields='id'
            ).execute().get('id')
        except Exception as e:
            logger.info('Could not add user {} due to : {}'.format(member_email, e))
            res = e
        return res

    def ensure_iam_robot_owner(self):
        """Add a member to a team drive."""
        if self.gsuite_api is None:
            self.authenticate()
        # For now assume we only give write.

        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Add the IAM robot to the drive as owner.',
            operation='PUT',
            drive_name=self.drive_name,
            detail=None
        )

        if interactive_result is False:
            return None

        if self.environment == 'production':
            logger.info('prod configuration active.')
            email = 'iam-robot@mozilla.com'
        elif self.environment == 'development':
            logger.info('dev configuration active.')
            email = 'iam-robot@test.mozilla.com'
        else:
            email = os.getenv('delegated_credentials')

        role = 'organizer'
        body = {'type': 'user', 'role': role, 'emailAddress': email}
        drive = self.find()

        return self.gsuite_api.permissions().create(
            body=body, fileId=drive.get('id'),
            supportsTeamDrives=True,
            useDomainAdminAccess=True,
            fields='id'
        ).execute()

    def member_remove(self, member_email):
        """Remove a member from a team drive."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Remove a member from a teamDrive.',
            operation='PUT',
            drive_name=self.drive_name,
            detail=member_email
        )

        if interactive_result is False:
            return None

        if self.gsuite_api is None:
            self.authenticate()

        # Do not strip owner.
        if member_email == 'iam_robot@test.mozilla.com' or member_email == 'iam_robot@mozilla.com':
            return None

        drive = self.find()
        permission_id = self._email_to_permission_id(member_email)
        return self.gsuite_api.permissions().delete(
            fileId=drive.get('id'),
            permissionId=permission_id,
            supportsTeamDrives=True,
            useDomainAdminAccess=True
        ).execute()

    def reconcile_members(self, member_list):
        """Reconcile the list of current members with a list of emails."""
        interactive_result = ask_question(
            interactive_mode=self.interactive_mode,
            message='Reason about membership.',
            operation='localhost',
            drive_name=self.drive_name,
            detail=None
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
                noops.append(member)
            elif member not in current_drive_members:
                additions.append(member)
            else:
                pass

        for member in current_drive_members:
            if member not in member_list:
                removals.append(member)

        proposal = {'additions': additions, 'removals': removals, 'noops': noops}
        logger.info("Membership list built: {}".format(proposal))
        return proposal

    def execute_proposal(self, reconciled_dictionary):
        """Carries out the addition, deletions, and noops."""
        if reconciled_dictionary['additions'] is not []:
            interactive_result = ask_question(
                interactive_mode=self.interactive_mode,
                message='Add all new members to the drive.',
                operation='LOCAL',
                drive_name=self.drive_name,
                detail=reconciled_dictionary['additions']
            )

            if interactive_result is False:
                pass
            else:
                for member in reconciled_dictionary['additions']:
                    logger.info('Adding member {} to {}.'.format(member, self.drive_name))
                    try:
                        self.member_add(member)
                    except Exception as e:
                        logger.error(e)
                        logger.error('Could not add member {} to {}.'.format(member, self.drive_name))

        if reconciled_dictionary['removals'] is not []:
            interactive_result = ask_question(
                interactive_mode=self.interactive_mode,
                message='Remove batch of members from the drive.',
                operation='LOCAL',
                drive_name=self.drive_name,
                detail=reconciled_dictionary['removals']
            )

            if interactive_result is False:
                pass
            else:
                for member in reconciled_dictionary['removals']:
                    logger.info('Removing member {} from {}.'.format(member, self.drive_name))
                    try:
                        self.member_remove(member)
                    except Exception as e:
                        logger.error(e)
                        logger.info('Could not remove member {} from {}.'.format(member, self.drive_name))

    def _email_to_permission_id(self, email):
        for member in self.members:
            if email == member.get('emailAddress'):
                return member.get('id')

    def _membership_to_email_list(self, members):
        emails = []
        for member in members:
            emails.append(member.get('emailAddress'))
        return emails

    def authenticate(self):
        credentials = self._get_credentials()
        http = credentials.authorize(httplib2.Http())
        self.gsuite_api = discovery.build('drive', 'v3', http=http)
        logger.info('Authenticated with GSuite using service account: {}'.format(credentials))

    def _name_conformance(self, drive_name):
        if drive_name.startswith('prod_mozilliansorg') or drive_name.startswith('dev_mozilliansorg'):
            print('matched')
            if self.environment == 'development':
                group_name = drive_name.split('dev_mozilliansorg_')[1]
                publisher_name = 'mozilliansorg'  # XXX TBD some day support multiple publisher conformance
                new_name = 't_{}_{}'.format(group_name, publisher_name)
            else:
                group_name = drive_name.split('dev_mozilliansorg_')[1]
                publisher_name = 'mozilliansorg'  # XXX TBD some day support multiple publisher conformance
                new_name = '{}_{}'.format(group_name, publisher_name)
            return new_name
        else:
            return drive_name

    def _format_metadata(self, drive_name):
        return {'name': drive_name}

    def _get_credentials(self):
        """ Gets valid user credentials from stored file."""
        secret = get_secret('gsuite-driver.token', {'app': 'gsuite-driver'})
        secret_file = open('/tmp/{}'.format(SA_CREDENTIALS_FILENAME), 'w')
        secret_file.write(secret)
        secret_file.close()
        cred_dir = os.path.expanduser('/tmp/')
        credential_path = os.path.join(cred_dir, SA_CREDENTIALS_FILENAME)

        # This scope is basically drive admin.  There is no granualar scope
        # to facilitate team drive interaction.
        scopes = ['https://www.googleapis.com/auth/drive']

        credentials = ServiceAccountCredentials.from_json_keyfile_name(
            credential_path, scopes
        )

        if os.getenv('environment') == 'prod':
            logger.info('prod configuration active.')
            delegated_credentials = credentials.create_delegated('iam-robot@mozilla.com')
        elif os.getenv('environment') == 'dev':
            logger.info('dev configuration active.')
            delegated_credentials = credentials.create_delegated('iam-robot@test.mozilla.com')
        else:
            delegated_credentials = credentials.create_delegated(os.getenv('delegated_credentials'))
        return delegated_credentials

    def _generate_request_id(self):
        return str(uuid.uuid4())
