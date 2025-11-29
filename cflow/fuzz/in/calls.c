void foo(void);
void bar(void);

void foo(void) {
    bar();
}

void bar(void) {
    foo();
}

int main() {
    foo();
    return 0;
}
