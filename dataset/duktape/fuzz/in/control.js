// Control flow
for (var i = 0; i < 5; i++) {
    print(i);
}

var x = 10;
while (x > 0) {
    x--;
}

if (x === 0) {
    print("done");
} else {
    print("error");
}

switch (x) {
    case 0:
        print("zero");
        break;
    default:
        print("other");
}
