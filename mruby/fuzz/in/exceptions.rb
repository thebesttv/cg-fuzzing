# Exception handling
begin
  raise "test error"
rescue => e
  puts e.message
ensure
  puts "cleanup"
end
