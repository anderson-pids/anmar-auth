class AnmarAuthError(Exception):
    pass


class TokenInvalidError(AnmarAuthError):
    pass


class JWKSFetchError(AnmarAuthError):
    pass
