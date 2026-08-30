require "rexml/document"
def timed(label, xml, tag)
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    REXML::Document.new(xml)
    res = "ok"
  rescue => e
    res = "ERROR #{e.class}: #{e.message[0,50]}"
  end
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  puts "#{tag} #{label}: #{res} #{(t1-t0).round(3)}s (#{xml.bytesize/1024/1024}MB)"
end
payload = "<a/>" * 300000   # ~1.5MB of real content
k = 5000
shapes = {
  "dup_wellformed+payload"   => "<?xml version=\"1.0\"?>" * k + "<root>" + payload + "</root>",
  "dup_enc_alt+payload"      => ("<?xml version=\"1.0\" encoding=\"UTF-16LE\"?><?xml version=\"1.0\" encoding=\"UTF-16BE\"?>" * (k/2)) + "<root>" + payload + "</root>",
  "dup_enc_same+payload"     => "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" * k + "<root>" + payload + "</root>",
  "nospace_mid+payload"      => "<root>" + payload + "<?xml?>" + payload + "</root>",
  "nospace_decl_first"       => "<?xml?>" + "<root>" + payload + "</root>",
}
["v3.3.2", "v3.4.1", "v3.4.2"].each do |tag|
  shapes.each { |label, xml| timed(label, xml, tag) }
end
