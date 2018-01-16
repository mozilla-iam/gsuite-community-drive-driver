"""Mozilla GSuite Driver"""
import credstash
import httplib2
import logging
import os
import time
import uuid

from apiclient import discovery
from oauth2client.service_account import ServiceAccountCredentials

SA_CREDENTIALS_FILENAME = 'GDrive.json'
APPLICATION_NAME = 'Gdrive-Community-Test'

logger = logging.getLogger('gsuite-driver')


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

class TeamDrive(object):
    def __init__(self, drive_name):
        self.drive = None
        self.drive_name = drive_name
        self.drive_metadata = self._format_metadata(drive_name)
        self.gsuite_api = None

    def create(self):
        """Creates a new team drive."""
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
        if self.gsuite_api is None:
            self.authenticate()

        drive = self.find()
        result = self.gsuite_api.teamdrives().delete(teamDriveId=drive.get('id')).execute()
        return result

    def find(self):
        """Locates a team drive based on name."""
        if self.gsuite_api is None:
            self.authenticate()

        if self.drive is not None:
            logger.info('Drive already has been discovered returning self.drive: {}'.format(self.drive_name))
            return self.drive
        else:
            drives = []

            # Pull back the first page of drives
            result = self.gsuite_api.teamdrives().list(pageSize=100,useDomainAdminAccess=True).execute()

            while result.get('nextPageToken', None) is not None:
                for drive in result.get('teamDrives'):
                    drives.append(drive)

                logger.info('Drive not found in page.  Pulling next page: {}'.format(result.get('nextPageToken')))

                result = self.gsuite_api.teamdrives().list(
                    pageSize=100,pageToken=result.get('nextPageToken'),useDomainAdminAccess=True
                ).execute()

            for drive in result.get('teamDrives'):
                drives.append(drive)

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
        if self.gsuite_api is None:
            self.authenticate()

        drive = self.find()
        selector_fields = "permissions(kind,id,type,emailAddress,domain,role,allowFileDiscovery,displayName,photoLink,expirationTime,teamDrivePermissionDetails,deleted)"

        resp = self.gsuite_api.permissions().list(
            fileId=drive.get('id'), supportsTeamDrives=True,
            useDomainAdminAccess=True, fields=selector_fields
        ).execute()

        permissions = resp.get('permissions')
        return permissions

    def member_add(self, member_email):
        """Add a member to a team drive."""
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

        #return credentials
        if os.getenv('environment') == 'prod':
            logger.info('prod configuration active.')
            email = 'iam-robot@mozilla.com'
        elif os.getenv('environment') == 'dev':
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
            for member in reconciled_dictionary['additions']:
                logger.info('Adding member {} to {}.'.format(member, self.drive_name))
                try:
                    self.member_add(member)
                except Exception as e:
                    logger.error(e)
                    logger.error('Could not add member {} to {}.'.format(member, self.drive_name))


        if reconciled_dictionary['removals'] is not []:
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

    def _format_metadata(self, drive_name):
        return {'name': drive_name}

    def _get_credentials(self):
        """
        Gets valid user credentials from stored file.
        """
        secret = get_secret('gsuite-driver.token', {'app': 'gsuite-driver'})
        secret_file = open('/tmp/{}'.format(SA_CREDENTIALS_FILENAME),'w')
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

        #return credentials
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
