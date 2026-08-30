lib = ARGV[0] || "lib"
$LOAD_PATH.unshift(File.expand_path(lib, Dir.pwd))
require "rexml/parsers/baseparser"

cases = {
  "dup_wellformed" => ("<?xml version=\"1.0\"?>" * 20000) + "<root/>",
  "dup_no_version" => ("<?xml?>" * 20000) + "<root/>",
  "dup_space" => ("<?xml ?>" * 20000) + "<root/>",
  "dup_garbage" => ("<?xml garbage?>" * 20000) + "<root/>",
  "dup_unclosed_tail" => ("<?xml version=\"1.0\"?>" * 19999) + "<?xml version=\"1.0\"",
  "dup_mixed_enc" => ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" * 20000) + "<root/>",
  "dup_missing_gt" => ("<?xml version=\"1.0\"" * 20000) + "<root/>",
  "decl_after_pi" => ("<?xml version=\"1.0\"?><?foo?>" * 10000) + "<root/>",
}

cases.each do |name, xml|
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    p = REXML::Parsers::BaseParser.new(xml)
    count = 0
    while p.has_next?
      p.pull
      count += 1
      break if count > 50000
    end
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "#{name}: parsed #{count} events in #{((t1 - t0) * 1000).round(1)} ms"
  rescue => e
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    puts "#{name}: ERROR after #{((t1 - t0) * 1000).round(1)} ms: #{e.class}: #{e.message.to_s[0, 100]}"
  end
end