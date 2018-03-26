import logging

from driver import TeamDrive
from settings import get_config
from vault import People

logger = logging.getLogger(__name__)
logging.basicConfig(
   level=logging.INFO,
   format='%(asctime)s:%(levelname)s:%(name)s:%(message)s'
)


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
        community_drive_driver = TeamDrive(
            drive_name=None,
            environment=environment,
            interactive_mode=driver_mode
        )

        all_drives = community_drive_driver.all()

        for drive in all_drives:
            this_drive = TeamDrive(
                drive_name=drive.get('name'),
                environment=environment,
                interactive_mode=driver_mode
            )

            conformant_name = this_drive._name_conformance(
                drive_name=drive.get('name')
            )

            this_drive.update(drive.get('id'), conformant_name)

        return 'Completed conformance mode pass on the teamDrives.'

    logger.debug('Searching DynamoDb for people.')
    people = People()

    logger.debug('Filtering person list to groups.')
    groups = people.grouplist(filter=filter_prefix)

    for group in groups:
        logger.info('GSuite driver is active for drive: {}'.format(group.get('group')))

        drive_name = '{}_{}'.format(group.get('group'), filter_prefix)

        if environment == 'development':
            drive_name = 't_' + drive_name

        community_drive_driver = TeamDrive(
            drive_name=drive_name,
            environment=environment,
            interactive_mode=driver_mode
        )

        community_drive_driver.find_or_create()

        work_plan = community_drive_driver.reconcile_members(people.build_email_list(group))
        community_drive_driver.execute_proposal(work_plan)
