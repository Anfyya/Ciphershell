// 极简测试程序 - 无任何依赖
int main() {
    volatile int x = 1 + 1;
    return x == 2 ? 0 : 1;
}
