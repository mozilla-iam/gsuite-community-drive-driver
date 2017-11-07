"""Mozilla GSuite Driver"""
import httplib2
import logging
import os
import uuid

from apiclient import discovery
from oauth2client.service_account import ServiceAccountCredentials

SA_CREDENTIALS_FILENAME = 'GDrive.json'
APPLICATION_NAME = 'Gdrive-Community-Test'

logger = logging.getLogger(__name__)


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
            result = self.gsuite_api.teamdrives().list().execute()

            for drive in result.get('teamDrives'):
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
        resp = self.gsuite_api.permissions().list(fileId=drive.get('id'), supportsTeamDrives=True, fields=selector_fields).execute()
        permissions = resp.get('permissions')
        return permissions

    def member_add(self, member_email):
        """Add a member to a team drive."""
        if self.gsuite_api is None:
            self.authenticate()
        # For now assume we only give write.
        role = 'writer'
        body = {'type': 'user', 'role': role, 'emailAddress': member_email}
        drive = self.find()

        return self.gsuite_api.permissions().create(
            body=body, fileId=drive.get('id'),
            supportsTeamDrives=True, fields='id'
        ).execute().get('id')

    def member_remove(self, member_email):
        """Remove a member from a team drive."""
        if self.gsuite_api is None:
            self.authenticate()

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

        return {'additions': additions, 'removals': removals, 'noops': noops}

    def execute_proposal(self, reconciled_dictionary):
        """Carries out the addition, deletions, and noops."""
        for member in reconciled_dictionary['additions']:
            logger.info('Adding member {} to {}.'.format(member, self.drive_name))
            self.member_add(member)

        for member in reconciled_dictionary['removals']:
            logger.info('Removing member {} from {}.'.format(member, self.drive_name))
            self.member_remove(member)

    def _email_to_permission_id(self, email):
        for member in self.members:
            if emails == member.get('emailAddress'):
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
        logger.info('Authenticated with GSuite using service account: {}'.format(self.drive_name))

    def _format_metadata(self, drive_name):
        return {'name': drive_name}

    def _get_credentials(self):
        """
        Gets valid user credentials from stored file.
        """
        home_dir = os.path.expanduser('~')
        credential_dir = os.path.join(home_dir, '.credentials')
        credential_path = os.path.join(credential_dir, SA_CREDENTIALS_FILENAME)

        # This scope is basically drive admin.  There is no granualar scope
        # to facilitate team drive interaction.
        scopes = ['https://www.googleapis.com/auth/drive']

        credentials = ServiceAccountCredentials.from_json_keyfile_name(
            credential_path, scopes
        )

        delegated_credentials = credentials.create_delegated('me@andrewkrug.com')

        return delegated_credentials

    def _generate_request_id(self):
        return str(uuid.uuid4())
