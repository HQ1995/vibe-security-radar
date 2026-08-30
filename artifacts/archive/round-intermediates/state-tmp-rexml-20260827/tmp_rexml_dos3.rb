require "rexml/document"
n = (ARGV[0] || "200000").to_i
xml = "<?xml?>" * n + "<root>" + ("<a/>" * 400000) + "</root>"  # ~1.2MB decls + ~2MB payload
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
  REXML::Document.new(xml)
  res = "ok"
rescue => e
  res = "ERROR #{e.class}: #{e.message[0,50]}"
end
t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
puts "time=#{(t1-t0).round(3)}s res=#{res} size_mb=#{xml.bytesize/1024/1024}"
