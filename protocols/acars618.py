from byteProtocol import *
import re
import time


class Acars618Support(object):

    @staticmethod
    def int(cls, value):
        if isinstance(value, int):
            value = str(value)
        return value

    @staticmethod
    def tail(cls, value):
        if not isinstance(value, str):
            raise BadProtocolFieldType('tail', type(value), str)
        return value.rjust(cls.assembleSpecFields['tail'].maxLen, ".")

    @staticmethod
    def msn(cls, value):
        if isinstance(value, bool):
            if value:
                return MSN(useCache=False)
            else:
                return cls.assembleSpecFields['msn'].defaultValue

        if not isinstance(value, str):
            raise BadProtocolFieldType('msn', type(value), str)

        return value


class Acars618Assembler(ByteProtocolAssembler):

    assembleSpecFields = {
        # name : FieldSpec( mn, mx , inputTypes, isRequired, defaultValue, assembleCallback)
        "soh": FieldSpec(1, 1, (str,), True, "\x01", None),
        "mode": FieldSpec(1, 1, (str, int), True, "2", Acars618Support.int),
        "tail": FieldSpec(7, 7, (str,), True, "N123456", Acars618Support.tail),
        "ack": FieldSpec(1, 1, (str,), True, "\x15", None),
        "label": FieldSpec(1, 1, (str,), True, "H1", None),
        "dbi": FieldSpec(1, 1, (str, int), False, "1", Acars618Support.int),
        "sot": FieldSpec(1, 1, (str,), True, "\x02", None),
        "msn": FieldSpec(4, 4, (str, bool), True, "M01A", Acars618Support.msn),
        "agency": FieldSpec(2, 2, (str,), True, "UA", None),
        "flight": FieldSpec(4, 4, (str, int), True, "9090", None),
        "text": FieldSpec(1, 220, (str,), False, None, None),
        "trailer": FieldSpec(1, 1, (str,), True, "\x03", None),
    }

    assembleGenFields = {"rn": "\r\n",
                         "sp": " ",
                         "dot": "."}

    # protocol specification in field order (all fields)
    assembleFieldOrder = ("soh", "mode", "tail", "ack", "label", "dbi", "sot",
                          "msn", "agency", "flight", "text", "trailer")


class Acars620Parser(ByteProtocolParser):

    minLength = 20

    # Protocol specific fields of interest (to be named)
    parseSpecFields = {"soh": "\x01",
                       "mode": "[!a-zA-Z0-9]{1}",
                       "tail": "[!a-zA-z0-9\.\-]{7}",
                       "ack": "[!a-zA-Z\x15\x06]{1}",
                       "label": "[!a-zA-Z0-9_\x7f]{2}",
                       "dbi": "[!a-zA-Z0-9]{0,1}",
                       "sot": "\x02",
                       "msn": "[!a-zA-Z0-9]{4}",
                       "agency": "[!a-zA-Z0-9$]{2}",
                       "flight": "[!a-zA-Z0-9 ]{4}",
                       "text": "[^\x03\x17]*",
                       "trailer": "[\x03\x17]{1}",
                       }

    # Protocol specific repeating fields (not to be named)
    parseGenFields = {}

    # protocol specification named + unnamed field order
    parseFieldOrder = ("soh", "mode", "tail", "ack", "label", "dbi", "sot",
                      "msn", "agency", "flight", "text", "trailer")

    # Fields which can be safely censored upon multiple reruns of the same test
    parseCensorFields = ("dbi", "msn")

    parseNamedFields, parsePattern, parseReObj = initParserFields(parseSpecFields, parseGenFields, parseFieldOrder)


class Acars618(Acars620Parser, Acars618Assembler):
    pass
