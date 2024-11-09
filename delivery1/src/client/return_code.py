from enum import Enum

class ReturnCode(Enum):
    '''UNIX semantic return codes'''
    SUCCESS = 0
    INPUT_ERROR = 1
    REPOSITORY_ERROR = -1