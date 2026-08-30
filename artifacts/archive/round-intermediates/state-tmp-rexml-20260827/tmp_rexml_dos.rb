require "rexml/document"
n = ARGV[0] ? ARGV[0].to_i : 20000
xml = "<?xml?>" * n + "<root/>"
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
  REXML::Document.new(xml)
  res = "ok"
rescue => e
  res = "ERROR #{e.class}: #{e.message[0,60]}"
end
t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
puts "#{res} time=#{(t1-t0).round(3)}s n=#{n}"
