class GSuiteDriverError(Exception):
    """ Base Error Class """

    pass


class DriveNameLockedError(GSuiteDriverError):
    """
    Raised when connector attempts to recycle a drive that has already been used.
    """

    def __init__(self, key, value, reason="drive name is locked."):
        msg = 'Drive name is locked "{}: {}" {}'.format(key, value, reason)
        GSuiteDriverError.__init__(self, msg)
