import json
import utils
import re

from apiclient.errors import HttpError
from driver import AuditTrail
from driver import TeamDrive
from exceptions import DriveNameLockedError
from settings import get_config
from vault import People

config = get_config()

custom_logger = utils.CISLogger(
    name=__name__,
    level=config('logging_level', namespace='cis', default='INFO'),
    cis_logging_output=config('logging_output', namespace='cis', default='cloudwatch'),
    cis_cloudwatch_log_group=config('cloudwatch_log_group', namespace='cis', default='staging')
).logger()

logger = custom_logger.get_logger()


def handle(event=None, context={}):
    logger.info('Initializing a run for the community team drive connector.')

    logger.debug('Getting configuration from environment.')
    config = get_config()

    filter_prefix = config('prefix', namespace='gsuite_driver', default='mozilliansorg')
    driver_mode = config('interactive', namespace='gsuite_driver', default='True')
    environment = config('environment', namespace='gsuite_driver', default='development')
    conformance = config('conformance', namespace='gsuite_driver', default='True')

    if conformance == 'True':
        """Perform a conformance pass on the drives.  Ensure naming standards etc."""
        audit = AuditTrail()

        community_drive_driver = TeamDrive(
            drive_name=None,
            environment=environment,
            interactive_mode=driver_mode
        )

        all_drives = community_drive_driver.all()

        audit.populate(all_drives)

        for drive in all_drives:
            this_drive = TeamDrive(
                drive_name=drive.get('name'),
                environment=environment,
                interactive_mode=driver_mode
            )

            try:
                conformant_name = this_drive._name_conformance(
                    drive_name=drive.get('name')
                )

                this_drive.update(drive.get('id'), conformant_name)
            except Exception as e:
                logger.error('Could not update drive due to: {}'.format(e))

        return 'Completed conformance mode pass on the teamDrives.'

    logger.debug('Searching DynamoDb for people.')
    people = People()

    logger.debug('Filtering person list to groups.')
    groups = people.grouplist(filter_prefix)

    community_drive_driver = TeamDrive(drive_name=None, environment=environment, interactive_mode=driver_mode)

    added = 0
    removed = 0
    noops = 0

    for group in groups:
        logger.info('GSuite driver is active for drive: {}'.format(group.get('group')))

        proposed_name = re.sub(r"^{}_".format(filter_prefix), "", group.get('group'))
        drive_name = '{}_{}'.format(proposed_name, filter_prefix)

        if environment == 'development':
            drive_name = 't_' + drive_name
        try:
            community_drive_driver.drive_name = drive_name.rstrip()
            logger.info('The drive name is: {}'.format(community_drive_driver.drive_name))
            community_drive_driver.drive_metadata = community_drive_driver._format_metadata(drive_name)

            community_drive_driver.find_or_create()
            email_list = people.build_email_list(group)
            work_plan = community_drive_driver.reconcile_members(email_list)

            added = added + len(work_plan.get('additions'))
            removed = removed + len(work_plan.get('removals'))
            noops = noops + len(work_plan.get('noops'))

            logger.info('Proposed plan is : {} for drive: {}'.format(work_plan, group.get('group')))
            community_drive_driver.execute_proposal(work_plan)
            community_drive_driver.drive = None
        except DriveNameLockedError:
            logger.warn('Skipping drive due to locked name: {}'.format(drive_name))
        except HttpError as e:
            logger.error('Could not interact with drive: {} due to : {}'.format(drive_name, e))
        except Exception as e:
            logger.error('Complete failure to reason about drive: {} due to : {}'.format(drive_name, e))

    logger.info(
        json.dumps(
            dict(
                component='teamDrive-connector',
                groups_managed=len(groups),
                profiles_managed=(len(people.table.all)),
                added=added,
                removed=removed,
                noops=noops
            )
        )
    )
    return None
