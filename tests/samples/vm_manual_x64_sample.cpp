extern "C" __declspec(noinline) int add(int a, int b) {
    return a + b;
}

extern "C" __declspec(noinline) int sub2(int a, int b) {
    return a - b;
}

extern "C" __declspec(noinline) int max2(int a, int b) {
    if (a > b) return a;
    return b;
}

extern "C" __declspec(noinline) int is_zero(int a) {
    if (a == 0) return 1;
    return 0;
}

extern "C" __declspec(noinline) int local1(int a) {
    int x = a + 3;
    return x;
}

int main() {
    volatile int sink = 0;
    sink += add(2, 5);
    sink += sub2(9, 4);
    sink += max2(7, 3);
    sink += is_zero(0);
    sink += local1(6);
    return sink == 29 ? 0 : 1;
}