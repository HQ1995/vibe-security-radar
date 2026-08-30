lib = ARGV[0] || "lib"
n = (ARGV[1] || 20000).to_i
$LOAD_PATH.unshift(File.expand_path(lib, Dir.pwd))
require "rexml/parsers/baseparser"
xml = ("<?xml version=\"1.0\"?>" * n) + "<root/>"
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
  p = REXML::Parsers::BaseParser.new(xml)
  count = 0
  while p.has_next?
    p.pull
    count += 1
    break if count > n + 5
  end
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  puts "parsed #{count} events in #{((t1 - t0) * 1000).round(1)} ms"
rescue => e
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  puts "ERROR after #{((t1 - t0) * 1000).round(1)} ms: #{e.class}: #{e.message.to_s[0, 200]}"
end