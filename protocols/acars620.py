from byteProtocol import *
import re
import time


class Acars620Support(object):

    @staticmethod
    def dest(cls, value):
        if isinstance(value, str):
            value = [value]
        return " ".join(value)

    @staticmethod
    def time(cls, value):
        return time.strftime("%d%H%M", time.gmtime())

    @staticmethod
    def tei(cls, value):
        if isinstance(value, str):
            return value

        if not isinstance(value, list):
            raise BadProtocolFieldType('tei', type(value), list)
        # requires format: [ (TEI, value), ...  ]
        return "/".join(["%s %s" % (tei.upper(), val) for (tei, val) in value])

    @staticmethod
    def text(cls, value):
        # Allow for None and string values
        if value and not isinstance(value, str):
            raise BadProtocolFieldType('text', type(value), str)
        elif not value:
            value = ""
        return "- " + value


class Acars620Assembler(ByteProtocolAssembler):

    assembleSpecFields = {
        # name : FieldSpec( mn, mx , inputTypes, isRequired, defaultValue, assembleCallback)
        "soh": FieldSpec(1, 1, (str,), True, "\x01", None),
        "priority": FieldSpec(2, 2, (str,), True, "QU", None),
        "adns": FieldSpec(7, None, (str, list), True, "DDLXCXA", Acars620Support.dest),
        "originator": FieldSpec(7, 7, (str,), True, "BBBBBBB", None),
        "time": FieldSpec(6, 6, (str,), True, None, Acars620Support.time),
        "sot": FieldSpec(1, 1, (str,), True, "\x02", None),
        "smi": FieldSpec(1, None, (str,), True, "AGM", None),
        "tei": FieldSpec(1, None, (str, list), True, None, Acars620Support.tei),
        "text": FieldSpec(1, 220, (str,), False, None, Acars620Support.text),
        "trailer": FieldSpec(1, 1, (str,), True, "\x03", None),
    }

    assembleGenFields = {"rn": "\r\n",
                         "sp": " ",
                         "dot": "."}

    # protocol specification in field order (all fields)
    assembleFieldOrder = ("soh", "priority", "sp", "adns", "rn", "dot", "originator",
                          "sp", "time", "rn", "sot", "smi", "rn", "tei", "rn", "text",
                          "rn", "trailer")


class Acars620Parser(ByteProtocolParser):

    minLength = 44

    # Protocol specific fields of interest (to be named)
    parseSpecFields = {"soh": "\x01",
                       "priority": "QU",
                       "adns": "([!a-zA-z0-9]{7}[ ]{0,1})+",
                       "originator": "[!a-zA-z0-9]{7}",
                       "time": "[!0-9]{6}",
                       "sot": "\x02",
                       "smi": "[!a-zA-Z0-9~]{3}",
                       "tei": "[!a-zA-Z0-9\s/\-]+",
                       "text": "([^\x03\x17]*){0,1}",
                       "trailer": "[\x03\x17]{1}",
                       }

    parseGenFields = {"rn": "\s\s",
                      "sp": "[ ]{1}",
                      "dot": "\."}

    # protocol specification named + unnamed field order
    parseFieldOrder = ("soh", "priority", "sp", "adns", "rn", "dot", "originator",
                       "sp", "time", "rn", "sot", "smi", "rn", "tei", "rn", "text",
                       "rn", "trailer")

    # Fields which can be safely censored upon multiple reruns of the same test
    parseCensorFields = ("time",)

    parseNamedFields, parsePattern, parseReObj = initParserFields(parseSpecFields, parseGenFields, parseFieldOrder)


class Acars620(Acars620Parser, Acars620Assembler):
    pass
