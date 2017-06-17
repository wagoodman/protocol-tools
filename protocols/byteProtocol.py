import re
import abc
import collections
import protocol

###############################################################################
# Exceptions

class ProtocolError(Exception):
   description = None
   def __str__(self):
      return self.description

class MissingRequiredProtocolField(ProtocolError):
   description = "Expected field '%s' was not found!"
   def __init__(self, fieldName):
      self.description = self.description % str(fieldName)

class BadProtocolField(ProtocolError):
   description = "Unexpected field name '%s' provided!"
   def __init__(self, fieldName):
      self.description = self.description % str(fieldName)

class BadProtocolFieldType(ProtocolError):
   description = "Unexpected type for field '%s' found '%s'. Expected '%s' instead."
   def __init__(self, fieldName, fieldType, expectedType):
      self.description = self.description % (str(fieldName), str(fieldType), str(expectedType))

class BadReplaceLength(ProtocolError): pass


###############################################################################
# Assembler

FieldSpec = collections.namedtuple('FieldSpec', ['minLen', 'maxLen', 'inputTypes', 'isRequired', 'defaultValue', 'assembleCallback'])

class ByteProtocolAssembler(protocol.ProtocolAssembler):

   assembleSpecFields = None

   assembleGenFields = None

   assembleFieldOrder = None

   @classmethod
   def assemble(protocolCls, fields):
      assembledMsg = ""
      for field in protocolCls.assembleFieldOrder:

         if field in protocolCls.assembleGenFields:
            item = protocolCls.assembleGenFields[field]

         else:
            if field not in protocolCls.assembleSpecFields:
               raise BadProtocolField(field)

            protocolField = protocolCls.assembleSpecFields[field]

            # Get value...
            item = None
            if field in fields:
               item = fields[field]
            if not item:
               item = protocolField.defaultValue

            # Process value before assembly...
            if protocolField.assembleCallback:
               item = protocolField.assembleCallback(protocolCls, item)

            # By this point, the item must be a string or None...
            if item and not isinstance(item, str):
               raise BadProtocolFieldType(field, type(item), str)

            # If the field is None but is required, there is an issue...
            if not item and protocolField.isRequired:
               raise MissingRequiredProtocolField(field)
            # The field is not required and not provided...
            elif not item and not protocolField.isRequired:
               continue

         assembledMsg += item

      return assembledMsg


###############################################################################
# Parser

def initParserFields(parseSpecFields, parseGenFields, parseFieldOrder):
   # Name each regex field in the protocol
   parseNamedFields = { field: "(?P<%s>%s)" % (field, regex) for field, regex in parseSpecFields.items() }

   # regular expression parsePattern
   parsePattern = "".join([ parseNamedFields[field] if field in parseNamedFields else parseGenFields[field] for field in parseFieldOrder ])

   # regular expression object
   parseReObj = re.compile(parsePattern, re.VERBOSE|re.MULTILINE)

   return parseNamedFields, parsePattern, parseReObj


class ByteProtocolParser(protocol.ProtocolParser):
   __metaclass__ = abc.ABCMeta

   ##########################################################################
   # Manually defined...

   minLength = None
   #maxLength = None

   # Protocol-specific fields of interest (to be grouped name in the regex)
   # { fieldName : regex }
   parseSpecFields = None

   # Protocol specific repeating/non-unique fields (not to be named)
   # { fieldName : regex }
   parseGenFields = None

   # protocol specification named + unnamed field order
   # [list of field names]
   parseFieldOrder = None

   # Fields which can be safely censored upon multiple reruns of the same test
   # [list of field names]
   parseCensorFields = None

   ##########################################################################
   # Automatically generated...

   # Name of each regex field in the protocol (built off of 'parseSpecFields' automatically)
   parseNamedFields = None

   # regular expression parsePattern for parsing
   parsePattern = None

   # regular expression object for parsing
   parseReObj = None

   @classmethod
   def fields(protocolCls):
      return protocolCls.parseSpecFields.keys()

   @classmethod
   def detect(protocolCls, caseString):
      values, spans = None, None

      if caseString < protocolCls.minLength:
         return values, spans

      matches = protocolCls.parseReObj.search(caseString)
      if matches:
         spans  = {}
         values = {}
         for g, value in matches.groupdict().items():
            spans[g]  = matches.span(g)
            values[g] = value

      return values, spans

   @classmethod
   def difference(protocolCls, caseString1, caseString2, ignoreFields=[]):
      differences = []

      for field in ignoreFields:
         if field not in protocolCls.fields():
            raise BadProtocolField(field)

      if caseString1 == caseString2:
         return differences

      values1, spans1 = protocolCls.detect(caseString1)
      values2, spans2 = protocolCls.detect(caseString2)

      if not (values1 and spans1 and values2 and spans2):
         return protocolCls.fields()

      for field in protocolCls.fields():
         if field not in ignoreFields:
            if values1[field] != values2[field]:
               differences.append(field)

      return differences


   @classmethod
   def mutate(protocolCls, caseString, replaceFields={}):
      mutatedCaseString = caseString

      if len(replaceFields.keys()) == 0:
         return mutatedCaseString

      for field in replaceFields:
         if field not in protocolCls.fields():
            raise BadProtocolField(field)

      values, spans = protocolCls.detect(caseString)

      if not (values and spans):
         return mutatedCaseString

      mutatedCaseString = list(mutatedCaseString)
      for field in protocolCls.fields():
         if field in replaceFields:
            start, end = spans[field]
            replacement = replaceFields[field]
            if len(replacement) != (end - start):
               raise BadReplaceLength
            mutatedCaseString[start:end] = replacement

      return "".join(mutatedCaseString)


   @classmethod
   def censor(protocolCls, caseString, parseCensorFields=None):

      if parseCensorFields == None:
         parseCensorFields = protocolCls.parseCensorFields

      mutatedCaseString = caseString

      if len(parseCensorFields) == 0:
         return mutatedCaseString

      for field in parseCensorFields:
         if field not in protocolCls.fields():
            raise BadProtocolField(field)

      values, spans = protocolCls.detect(caseString)

      if not (values and spans):
         return mutatedCaseString

      mutatedCaseString = list(mutatedCaseString)
      for field in protocolCls.fields():
         if field in parseCensorFields:
            start, end = spans[field]
            replacement = ["!"]*(end - start)
            if len(replacement) != (end - start):
               raise BadReplaceLength
            mutatedCaseString[start:end] = replacement

      return "".join(mutatedCaseString)
