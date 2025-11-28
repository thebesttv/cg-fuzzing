# Methods
def add(a, b)
  a + b
end

result = add(1, 2)
puts result

# Lambda
mul = ->(a, b) { a * b }
puts mul.call(3, 4)
