
class DXFError(Exception):
    pass

class DXFUnexpectedError(DXFError):
    def __init__(self, got, expected):
        self._got = got
        self._expected = expected

class DXFUnexpectedStatusCodeError(DXFUnexpectedError):
    def __str__(self):
        return 'expected status code %d, got %d' % (self._expected, self._got)

class DXFDigestMismatchError(DXFUnexpectedError):
    def __str__(self):
        return 'expected digest %s, got %s' % (self._expected, self._got)

class DXFUnexpectedKeyTypeError(DXFUnexpectedError):
    def __str__(self):
        return 'expected key type %s, got %s' % (self._expected, self._got)

class DXFUnexpectedDigestMethodError(DXFUnexpectedError):
    def __str__(self):
        return 'expected digest method %s, got %s' % (self._expected, self._got)

class DXFDisallowedSignatureAlgorithmError(DXFError):
    def __init__(self, alg):
        self.alg = alg

    def __str__(self):
        return 'disallowed signature algorithm: %s' % self.alg

class DXFChainNotImplementedError(DXFError):
    def __str__(self):
        return 'verification with a cert chain is not implemented'

class DXFUnauthorizedError(DXFError):
    pass
