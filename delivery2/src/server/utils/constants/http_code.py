class HTTP_Code:
    """ HTTP Code Constants """
    OK = 200                    # The request succeeded. 
    CREATED = 201               # The request succeeded, and a new resource was created as a result.
    BAD_REQUEST = 400           # The server could not understand the request due to invalid syntax.
    UNAUTHORIZED = 401          # The client must authenticate itself to get the requested response.
    FORBIDDEN = 403             # The client does not have access rights to the content.
    NOT_FOUND = 404             # The server can not find the requested resource.