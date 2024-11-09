from enum import Enum

class httpMethod(Enum):
    GET = "get",
    POST = "post",
    PUT = "put",
    DELETE = "delete"

    def __init__(self, method):
        self._method = method

    @property
    def method(self) -> str:
        return self._method