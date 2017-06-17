from protocols.acars618 import Acars618
from protocols.acars620 import Acars620

example618 = '\x012WG12321\x15H11\x02M01AUA9191Hello, world! From: the sky!\x03'
parsedFields = Acars618.detect(example618)

is618Msg = parsedFields != (None, None)
print "Is an ACARS 618 message?", is618Msg
if is618Msg:
    values, spans = parsedFields
    for field, value in values.items():
        print "   %10s: %s" % (field, repr(value))

    reassembled618 = Acars618.assemble(parsedFields[0])

    print "Original Message:   ", repr(example618)
    print "Reassembled Message:", repr(reassembled618)

print
example620   = '\x01QU DDLXCXA\r\n.BBBBBBB 172038\r\n\x02AGM\r\nAN N123456\r\n- \r\n\x03'
parsedFields = Acars620.detect(example620)

is620Msg = parsedFields != (None, None)
print "Is an ACARS 6120 message?", is620Msg
if is620Msg:
    values, spans = parsedFields
    for field, value in values.items():
        print "   %10s: %s" % (field, repr(value))

    reassembled620 = Acars620.assemble(parsedFields[0])

    print "Original Message:   ", repr(example620)
    print "Reassembled Message:", repr(reassembled620)
