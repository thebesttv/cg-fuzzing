#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int helper(int x) {
    return x * 2;
}

int compute(int a, int b) {
    return MAX(helper(a), MIN(b, 100));
}

int main() {
    return compute(5, 10);
}
