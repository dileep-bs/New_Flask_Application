class InvalidCredencials(Exception):
    def __init__(self,message):
        super(InvalidCredencials, self).__init__(message)


class TokenExpired(Exception):
    def __init__(self,message):
        super(TokenExpired, self).__init__(message)


class DataNotSufficient(Exception):
    def __init__(self,message):
        super(DataNotSufficient, self).__init__(message)