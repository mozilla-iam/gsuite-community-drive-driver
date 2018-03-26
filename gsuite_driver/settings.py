from everett.manager import ConfigManager
from everett.manager import ConfigOSEnv

"""
:mod:`gsuite-driver.settings` -- GSuite Driver Configuration
* Environment variables used
* GSUITE_DRIVER_PREFIX
"""


def get_config():
    return ConfigManager(
        [
            ConfigOSEnv()
        ]
    )
