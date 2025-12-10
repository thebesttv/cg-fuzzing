typedef void (*callback_t)(int);

void handler(int x) {
    if (x > 0) {
        handler(x - 1);
    }
}

void process(callback_t cb, int val) {
    cb(val);
}

int main() {
    process(handler, 5);
    return 0;
}
