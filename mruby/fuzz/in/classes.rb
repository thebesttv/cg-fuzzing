# Classes
class Animal
  attr_accessor :name
  
  def initialize(name)
    @name = name
  end
  
  def speak
    puts "#{@name} says hello"
  end
end

dog = Animal.new("Dog")
dog.speak
