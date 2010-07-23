def replace_in_file filename, regex, value
  spec = File.read(filename)
  File.open(filename, "w") do |file|
    file.write spec.gsub(regex, value)
  end
end

puts "================= #{ARGV[0]}"
replace_in_file "./jdigidoc/jdigidoc/src/main/java/ee/sk/digidoc/Version.java", /LIB_VERSION.*/, "LIB_VERSION = \"#{ARGV[0]}\";"
