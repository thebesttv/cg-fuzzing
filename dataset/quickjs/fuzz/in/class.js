class Animal {
  constructor(name) { this.name = name; }
  speak() { console.log(this.name); }
}
let dog = new Animal("dog");
dog.speak();
