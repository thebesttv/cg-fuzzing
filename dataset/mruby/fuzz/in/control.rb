# Control flow
5.times do |i|
  puts i
end

x = 10
while x > 0
  x -= 1
end

if x == 0
  puts "done"
else
  puts "error"
end

case x
when 0
  puts "zero"
else
  puts "other"
end
