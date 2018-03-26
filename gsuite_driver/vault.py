import boto3
import logging

from boto3.dynamodb.conditions import Attr

try:
    from settings import get_config
except ImportError:
    from gsuite_driver.settings import get_config

logger = logging.getLogger(__name__)


class CISTable(object):
    def __init__(self, table_name):
        self.boto_session = boto3.session.Session()
        self.table_name = table_name
        self.table = None

    def connect(self):
        resource = self.boto_session.resource('dynamodb')
        self.table = resource.Table(self.table_name)
        return self.table

    @property
    def all(self):
        if self.table is None:
            self.connect()

        response = self.table.scan(
                FilterExpression=Attr('active').eq(True)
            )

        users = response.get('Items')

        while 'LastEvaluatedKey' in response:
            response = self.table.scan(
                FilterExpression=Attr('active').eq(True),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            users.extend(response['Items'])

        logger.debug('Returning total: {} users from the identity vault.'.format(len(users)))
        return users


class People(object):
    def __init__(self):
        self.config = get_config()
        self.table_name = self.config('dynamodb_person_table', namespace='cis', default='fake-identity-vault')
        self.table = CISTable(self.table_name)

    def grouplist(self, filter=None):
        """Returns a list of dicts of for each group id, email"""
        self.master_grouplist = self._extract_groups(filter)

        for record in self.table.all:
            if record.get('groups') != []:
                self._add_record_to_groups(record)
            else:
                pass

        logger.debug('Returning total of : {} groups for this run of the connector.'.format(
            len(self.master_grouplist))
        )
        return self.master_grouplist

    def _add_record_to_groups(self, user_record):
        for group in user_record.get('groups', []):
            if self._is_in_masterlist(group):
                group_idx = self._locate_group_index(group)
                self.master_grouplist[group_idx]['members'].append(user_record)

    def _is_in_masterlist(self, group):
        for this_group in self.master_grouplist:
            if group == this_group.get('group'):
                return True
            else:
                return False

    def _locate_group_index(self, group_name):
        for group in self.master_grouplist:
            if group_name == group['group']:
                return self.master_grouplist.index(group)

    def _filter_group(self, group_name, filter=None):
        if filter is not None:
            group_name = group_name
            try:
                group_prefix = group_name.split('_')[0]

                if group_prefix != filter:
                    return False

                if group_prefix == filter:
                    return True

            except AttributeError:
                return False
        else:
            return True

    def _extract_groups(self, filter=None):
        unique_groups = []
        for record in self.table.all:
            groups = record.get('groups', [])

            if groups == []:
                continue
            else:
                for group in groups:
                    proposed_group = {
                        'group': group,
                        'members': []
                    }

                    if self._filter_group(group, filter):
                        if proposed_group not in unique_groups:
                            unique_groups.append(proposed_group)
                        else:
                            pass
        return unique_groups

    def build_email_list(self, group_dict):
        memberships = []
        for member in group_dict['members']:
            if member.get('primaryEmail').split('@')[1] == 'mozilla.com':
                memberships.append(member.get('primaryEmail'))
                continue

            if member.get('primaryEmail').split('@')[1] == 'mozillafoundation.org':
                memberships.append(member.get('primaryEmail'))
                continue

            for email in member['emails']:
                if email.get('verified') is not True:
                    logger.info('Skipping processing unverified email for member: {}'.format(email['value']))
                else:
                    if email['value'].split('@')[1] == 'mozilla.com':
                        memberships.append(email['value'])
                    elif email['name'] == 'Google Provider':
                        memberships.append(email['value'])
                    else:
                        logger.info('Could not reason about user: {}'.format(email['value']))
            continue
        logger.debug('Returning complete list of memberships for group: {}.'.format(group_dict.get('group')))
        return memberships
