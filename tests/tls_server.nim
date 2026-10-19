## A standalone HTTP/WebSocket fixture driven by test_tls.rb (no third-party client).
import std/[os, strutils], mummy

var server: Server
var stop: Channel[bool]
stop.open()

proc handler(request: Request) {.gcsafe.} =
  case request.path
  of "/healthz": request.respond(200, body = "ok")
  of "/echo": request.respond(200, body = request.body)
  of "/ws": discard request.upgradeToWebSocket()
  of "/stop":
    request.respond(200, body = "stopping")
    stop.send(true)
  else: request.respond(404)

proc socketHandler(ws: WebSocket, event: WebSocketEvent, message: Message) {.gcsafe.} =
  if event == MessageEvent:
    if message.kind in {TextMessage, BinaryMessage}:
      ws.send(message.data, message.kind)
    elif message.kind == Ping: ws.send(message.data, Pong)

let tls = if paramCount() > 1:
  TlsConfig(certificateFile: paramStr(2), privateKeyFile: paramStr(3),
            handshakeTimeoutMs: 300, shutdownTimeoutMs: 100, maxPendingHandshakes: 2)
  else: nil
server = newServer(handler, socketHandler, workerThreads = 2,
                   maxMessageLen = 8 * 1024 * 1024, maxBodyLen = 8 * 1024 * 1024, tls = tls)

proc stopper() {.thread.} =
  discard stop.recv()
  sleep(100)
  server.close()

var thread: Thread[void]
createThread(thread, stopper)
server.serve(Port(parseInt(paramStr(1))), "127.0.0.1")
joinThread(thread)
stop.close()
