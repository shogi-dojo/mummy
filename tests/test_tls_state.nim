import std/selectors
import mummy/tls

var connection: TlsConnection
connection.phase = tlsHandshake
connection.wait = tlsRead
doAssert tlsInterests(connection, true) == {Read}
connection.wait = tlsWrite
doAssert tlsInterests(connection, false) == {Write}
connection.phase = tlsOpen
connection.wait = tlsReady
doAssert tlsInterests(connection, false) == {Read}
doAssert tlsInterests(connection, true) == {Read, Write}
connection.writeWait = tlsRead
doAssert tlsInterests(connection, true) == {Read}
doAssert not satisfied(connection.writeWait, {Write})
connection.writeWait = tlsWrite
doAssert tlsInterests(connection, true) == {Write}
doAssert not satisfied(connection.writeWait, {Read})
connection.writeWait = tlsReady
connection.readWait = tlsWrite
doAssert tlsInterests(connection, true) == {Write}
connection.phase = tlsClosing
connection.wait = tlsRead
doAssert tlsInterests(connection, true) == {Read}

when not defined(ssl):
  import mummy/common
  doAssertRaises MummyError:
    discard newTlsContext(TlsConfig(certificateFile: "cert", privateKeyFile: "key"))
