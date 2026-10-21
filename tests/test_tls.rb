# Black-box HTTP/WebSocket transport tests; Ruby standard library only.
require 'base64'
require 'fileutils'
require 'net/http'
require 'openssl'
require 'socket'
require 'tempfile'
require 'tmpdir'
require 'timeout'

def free_port
  TCPServer.open('127.0.0.1', 0) { |socket| socket.addr[1] }
end

def exact(socket, length)
  result = ''.b
  while result.bytesize < length
    bytes = socket.read(length - result.bytesize)
    raise 'unexpected EOF' if bytes.nil? || bytes.empty?
    result << bytes
  end
  result
end

def frame(payload, opcode = 2)
  size = payload.bytesize
  header = [0x80 | opcode].pack('C')
  header << if size < 126
              [0x80 | size].pack('C')
            elsif size <= 65_535
              [0xfe, size].pack('Cn')
            else
              [0xff, size].pack('CQ>')
            end
  mask = 'abcd'.bytes
  header + 'abcd' + payload.bytes.each_with_index.map { |value, i| value ^ mask[i % 4] }.pack('C*')
end

def receive(socket)
  opcode, size = exact(socket, 2).unpack('CC')
  raise 'masked server frame' unless (size & 0x80).zero?
  size &= 127
  size = exact(socket, 2).unpack1('n') if size == 126
  size = exact(socket, 8).unpack1('Q>') if size == 127
  [opcode & 15, exact(socket, size)]
end

def connect(port, context)
  raw = TCPSocket.new('127.0.0.1', port)
  return raw unless context
  socket = OpenSSL::SSL::SSLSocket.new(raw, context)
  socket.sync_close = true
  socket.hostname = 'localhost'
  socket.connect
  socket.post_connection_check('localhost')
  socket
rescue StandardError
  raw.close if raw && !raw.closed?
  raise
end

def websocket(port, context)
  socket = connect(port, context)
  key = Base64.strict_encode64(OpenSSL::Random.random_bytes(16))
  socket.write("GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" \
               "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" \
               "Sec-WebSocket-Key: #{key}\r\n\r\n")
  header = ''.b
  header << exact(socket, 1) until header.end_with?("\r\n\r\n")
  raise header unless header.start_with?('HTTP/1.1 101')
  socket
end

def http(port, cert = nil)
  client = Net::HTTP.new('localhost', port, nil)
  client.open_timeout = client.read_timeout = 5
  if cert
    client.use_ssl = true
    client.ca_file = cert
    client.verify_mode = OpenSSL::SSL::VERIFY_PEER
  end
  client.start { |connection| yield connection }
end

def check(value, message = 'assertion failed')
  raise message unless value
end

def exercise(port, context, cert)
  http(port, cert) do |client|
    3.times { check(client.get('/healthz').body == 'ok') }
    body = (0..255).to_a.pack('C*') * 1024
    check(client.post('/echo', body, 'Content-Type' => 'application/octet-stream').body == body)
    # A backpressured response stream, chunk by chunk.
    streamed = 16.times.map { |i| (97 + i).chr * (64 * 1024 + i) }.join
    check(client.get('/stream-out').body == streamed, 'corrupt streamed response')
    # A request body read with pauses between chunks.
    upload = (0..255).to_a.pack('C*') * (16 * 1024)
    check(client.post('/stream-in', upload, 'Content-Type' => 'application/octet-stream').body == upload,
          'corrupt streamed request body')
    check(client.get('/healthz').body == 'ok')
  end

  socket = websocket(port, context)
  messages = 128.times.map { |i| "sequence-#{i}" }
  socket.write(messages.map { |message| frame(message) }.join)
  messages.each { |message| check(receive(socket) == [2, message]) }
  frame('fragmented ciphertext input').bytes.each_slice(3) { |bytes| socket.write(bytes.pack('C*')) }
  check(receive(socket) == [2, 'fragmented ciphertext input'])
  socket.write(frame('ping', 9))
  check(receive(socket) == [10, 'ping'])
  # A shared payload larger than one TLS write, queued twice behind ordinary frames.
  socket.write(frame('before', 2) + frame('shared:300000', 1) + frame('after', 2))
  check(receive(socket) == [2, 'before'])
  2.times { check(receive(socket) == [2, 's' * 300_000], 'corrupt shared payload') }
  check(receive(socket) == [2, 'after'])
  socket.write(frame('', 8))
  check(receive(socket)[0] == 8)
  socket.close

  # Block writes while additional frames arrive: an active retry buffer must not grow.
  slow = websocket(port, context)
  (context ? slow.to_io : slow).setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 8192)
  payloads = 32.times.map { |i| i.chr.b * (256 * 1024 + i) }
  sender = Thread.new { payloads.each { |data| slow.write(frame(data)) } }
  sleep 0.2
  http(port, cert) { |client| check(client.get('/healthz').body == 'ok') }
  # Reopen the receive window before draining: Linux's tiny-window delayed ACKs can make
  # the deliberate stall dominate the test for minutes, including on the plain baseline.
  (context ? slow.to_io : slow).setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 512 * 1024)
  payloads.each { |data| check(receive(slow) == [2, data], 'corrupt or reordered backpressured frame') }
  sender.value
  slow.close

  # Abrupt peers must not kill the process, including SIGPIPE during TLS writes.
  12.times do
    socket = websocket(port, context)
    socket.write(frame('reset' * 20_000))
    raw = context ? socket.to_io : socket
    raw.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack('ii'))
    raw.close
  end
  sleep 0.1
  http(port, cert) { |client| check(client.get('/healthz').body == 'ok') }
end

binary = File.expand_path(ARGV.fetch(0))
Dir.mktmpdir('mummy-tls-') do |directory|
  cert, key = %w[cert.pem key.pem].map { |file| File.join(directory, file) }
  check(system('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
               '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext',
               'subjectAltName=DNS:localhost,IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE',
               '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign',
               out: File::NULL, err: File::NULL))
  context = OpenSSL::SSL::SSLContext.new
  context.ca_file = cert
  context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  # An ECDSA leaf signed by the temporary RSA CA exercises complete PEM chain loading.
  leaf_key = OpenSSL::PKey::EC.generate('prime256v1')
  root = OpenSSL::X509::Certificate.new(File.read(cert))
  leaf = OpenSSL::X509::Certificate.new
  leaf.version, leaf.serial = 2, 2
  leaf.subject = OpenSSL::X509::Name.parse('/CN=localhost')
  leaf.issuer = root.subject
  leaf.public_key = leaf_key
  leaf.not_before, leaf.not_after = Time.now - 60, Time.now + 86_400
  extensions = OpenSSL::X509::ExtensionFactory.new
  extensions.subject_certificate, extensions.issuer_certificate = leaf, root
  leaf.extensions = [extensions.create_extension('basicConstraints', 'CA:FALSE', true),
                     extensions.create_extension('keyUsage', 'digitalSignature', true),
                     extensions.create_extension('extendedKeyUsage', 'serverAuth'),
                     extensions.create_extension('subjectAltName', 'DNS:localhost,IP:127.0.0.1')]
  leaf.sign(OpenSSL::PKey.read(File.read(key)), OpenSSL::Digest::SHA256.new)
  chain, ec_key = File.join(directory, 'chain.pem'), File.join(directory, 'ec-key.pem')
  File.write(chain, leaf.to_pem + root.to_pem)
  File.write(ec_key, leaf_key.to_pem)
  [:plain, :tls, :chain].each do |mode|
    secure = mode != :plain
    port = free_port
    log = Tempfile.new('mummy-output')
    credentials = mode == :chain ? [chain, ec_key] : [cert, key]
    pid = Process.spawn(binary, port.to_s, *(secure ? credentials : []), out: log, err: log)
    begin
      Timeout.timeout(10) do
        loop do
          begin
            connect(port, secure ? context : nil).close
            break
          rescue Errno::ECONNREFUSED
            sleep 0.03
          end
        end
      end
      Timeout.timeout(90) { exercise(port, secure ? context : nil, secure ? cert : nil) }
      if secure
        [OpenSSL::SSL::TLS1_2_VERSION, OpenSSL::SSL::TLS1_3_VERSION].each do |version|
          version_context = OpenSSL::SSL::SSLContext.new
          version_context.ca_file = cert
          version_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          version_context.min_version = version_context.max_version = version
          socket = connect(port, version_context)
          check(socket.ssl_version == (version == OpenSSL::SSL::TLS1_2_VERSION ? 'TLSv1.2' : 'TLSv1.3'))
          socket.close
        end
        legacy = OpenSSL::SSL::SSLContext.new
        legacy.min_version = legacy.max_version = OpenSSL::SSL::TLS1_1_VERSION
        legacy.ciphers = 'ALL:@SECLEVEL=0'
        begin
          unexpected = connect(port, legacy)
          unexpected.close
          raise 'TLS 1.1 accepted'
        rescue OpenSSL::SSL::SSLError
          # The listener requires TLS 1.2 or newer.
        end
        stalled = TCPSocket.new('127.0.0.1', port)
        sleep 0.5
        check(stalled.read(1).nil?, 'handshake did not expire')
        stalled.close
        stalled = 2.times.map { TCPSocket.new('127.0.0.1', port) }
        sleep 0.03
        begin
          unexpected = connect(port, context)
          unexpected.close
          raise 'handshake admission limit ignored'
        rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET
          # Admission is rejected before the handshake can complete.
        ensure
          stalled.each(&:close)
        end
        sleep 0.1
      end
      http(port, secure ? cert : nil) { |client| check(client.get('/stop').body == 'stopping') }
      _, status = Timeout.timeout(10) { Process.wait2(pid) }
      pid = nil
      check(status.success?, 'fixture failed during shutdown')
      puts "PASS #{mode == :chain ? 'HTTPS/WSS ECDSA certificate chain' : (secure ? 'HTTPS/WSS' : 'HTTP/WS')}"
    ensure
      if pid
        Process.kill('KILL', pid) rescue nil
        Process.wait(pid) rescue nil
        log.rewind
        warn log.read
      end
      log.close!
    end
  end
  [[cert, cert], [cert, key + '.missing']].each do |paths|
    Timeout.timeout(5) do
      check(!system(binary, free_port.to_s, *paths, out: File::NULL, err: File::NULL), 'invalid TLS config accepted')
    end
  end
  puts 'PASS invalid TLS configurations'
end
