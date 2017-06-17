# protocol-tools

Just a small collection of tools to parsing simple character oriented protocols.
ARINC 618 is a public communications spec that shows off what the `ByteProtocol`
class can do:

Easily create new messages from scratch:
```python
>>> message = Acars618.assemble({'text': 'Hello, world!', 'tail':'WG12345'})
>>> print "Message:", repr(message)
Message: '\x012WG12345\x15H11\x02M01AUA9090Hello, world!\x03'
```

Parse out a message into individual fields:
```python
>>> values, spans = parsedMessage = Acars618.detect(message)
>>> print "Fields:", repr(values)
Fields: {'dbi': '1', 'flight': '9090', 'ack': '\x15', 'soh': '\x01', 'agency': 'UA', 'label': 'H1', 'msn': 'M01A', 'tail': 'WG12345', 'mode': '2', 'text': 'Hello, world!', 'trailer': '\x03', 'sot': '\x02'}
```

Change selected fields of an example protocol string:
```python
>>> newMessage = Acars618.mutate(message, {'text': "I'm Replaced!"})
>>> print "New Message:", repr(newMessage)
New Message: "\x012WG12345\x15H11\x02M01AUA9090I'm Replaced!\x03"
```

Given two example strings, show the fields that have different values:
```python
>>> diffs = Acars618.difference(message, newMessage)
>>> print "Differences:", repr(diffs)
Differences: ['text']
```

Censor a selection of fields:
```python
>>> censoredMessage = Acars618.censor(message, parseCensorFields=['text', 'tail'])
>>> print "Censored Message", repr(censoredMessage)
Censored Message '\x012!!!!!!!\x15H11\x02M01AUA9090!!!!!!!!!!!!!\x03'
```
