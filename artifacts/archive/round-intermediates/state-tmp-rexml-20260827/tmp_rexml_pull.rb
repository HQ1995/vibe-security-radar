require "rexml/parsers/baseparser"
n = (ARGV[0] || "100000").to_i
xml = "<?xml?>" * n + "<root/>"
parser = REXML::Parsers::BaseParser.new(xml)
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
count = 0
while parser.has_next?
  parser.pull
  count += 1
end
t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
puts "time=#{(t1-t0).round(3)}s events=#{count} n=#{n} size_mb=#{(xml.bytesize/1048576.0).round(2)}"
