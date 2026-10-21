## A standalone HTTP/WebSocket fixture driven by test_tls.rb (no third-party client).
import std/[locks, os, strutils, tables], mummy

const streamedChunks = 16

var server: Server
var stop: Channel[bool]
stop.open()
var streamsLock: Lock
var streamsSent: Table[ResponseBodyStream, int]
initLock(streamsLock)

proc streamedChunk*(index: int): string =
  ## Chunk `index` of `/stream-out`: distinct bytes and lengths, so loss or reordering shows.
  repeat(char(ord('a') + index), 64 * 1024 + index)

proc handler(request: Request) {.gcsafe.} =
  case request.path
  of "/healthz": request.respond(200, body = "ok")
  of "/echo": request.respond(200, body = request.body)
  of "/ws": discard request.upgradeToWebSocket()
  of "/stream-out": discard request.respondStream()
  of "/stop":
    request.respond(200, body = "stopping")
    stop.send(true)
  else: request.respond(404)

proc requestBodyHandler(request: Request, stream: RequestBodyStream, event: RequestBodyEvent) {.gcsafe.} =
  ## `/stream-in` reads its body chunk by chunk. Each slow chunk pauses socket reads, so
  ## records OpenSSL already decrypted must be delivered when reading resumes.
  case event.kind
  of RequestBodyOpen:
    if request.path == "/stream-in": discard stream.accept()
  of RequestBodyChunk:
    request.body.add(event.data)
    sleep(2)
  of RequestBodyEnd:
    request.respond(200, body = request.body)
  of RequestBodyError: discard

proc responseBodyHandler(stream: ResponseBodyStream, event: ResponseBodyEventKind) {.gcsafe.} =
  case event
  of ResponseBodyOpen, ResponseBodyWritable:
    var index: int
    {.gcsafe.}:
      withLock streamsLock:
        index = streamsSent.getOrDefault(stream)
        streamsSent[stream] = index + 1
    if index < streamedChunks: discard stream.write(streamedChunk(index))
    else: stream.close()
  of ResponseBodyError, ResponseBodyClosed:
    {.gcsafe.}:
      withLock streamsLock:
        streamsSent.del(stream)

proc socketHandler(ws: WebSocket, event: WebSocketEvent, message: Message) {.gcsafe.} =
  if event == MessageEvent:
    if message.kind == TextMessage and message.data.startsWith("shared:"):
      # One immutable payload queued twice: each send keeps its own offset.
      let payload = newSharedPayload(repeat('s', parseInt(message.data[7 .. ^1])))
      ws.sendShared(payload)
      ws.sendShared(payload)
    elif message.kind in {TextMessage, BinaryMessage}:
      ws.send(message.data, message.kind)
    elif message.kind == Ping: ws.send(message.data, Pong)

let tls = if paramCount() > 1:
  TlsConfig(certificateFile: paramStr(2), privateKeyFile: paramStr(3),
            handshakeTimeoutMs: 300, shutdownTimeoutMs: 100, maxPendingHandshakes: 2)
  else: nil
server = newServer(handler, socketHandler, workerThreads = 2,
                   maxMessageLen = 8 * 1024 * 1024, maxBodyLen = 8 * 1024 * 1024,
                   requestBodyHandler = requestBodyHandler,
                   responseBodyHandler = responseBodyHandler, tls = tls)

proc stopper() {.thread.} =
  discard stop.recv()
  sleep(100)
  server.close()

var thread: Thread[void]
createThread(thread, stopper)
server.serve(Port(parseInt(paramStr(1))), "127.0.0.1")
joinThread(thread)
stop.close()
