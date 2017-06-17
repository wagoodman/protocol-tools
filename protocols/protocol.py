import abc


class ProtocolAssembler(object):
   __metaclass__ = abc.ABCMeta

   @classmethod
   @abc.abstractmethod
   def assemble(protocolCls, fields): pass


class ProtocolParser(object):
   __metaclass__ = abc.ABCMeta

   @classmethod
   @abc.abstractmethod
   def fields(protocolCls): pass

   @classmethod
   @abc.abstractmethod
   def detect(protocolCls, caseString): pass

   @classmethod
   @abc.abstractmethod
   def difference(protocolCls, caseString1, caseString2, ignoreFields=[]): pass

   @classmethod
   @abc.abstractmethod
   def mutate(protocolCls, caseString, replaceFields={}): pass

   @classmethod
   @abc.abstractmethod
   def censor(protocolCls, caseString, parseCensorFields=None): pass
