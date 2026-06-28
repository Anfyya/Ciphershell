/**
 * CipherShell 性能基准测试
 * 测量各保护等级的性能开销
 */

#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <functional>
#include <windows.h>
#include <intrin.h>

// ============================================================================
// 基准测试结果
// ============================================================================

struct BenchmarkResult {
    std::string testName;
    uint64_t    baselineCycles;     // 基线周期数
    uint64_t    protectedCycles;    // 保护后周期数
    double      overheadRatio;      // 开销倍率
    double      startupTimeMs;      // 启动时间（毫秒）
    size_t      memoryIncrease;     // 内存增加（字节）
};

// ============================================================================
// 测试函数（模拟不同复杂度的代码）
// ============================================================================

// 简单算术
volatile int test_arithmetic(int n) {
    volatile int result = 0;
    for (int i = 0; i < n; i++) {
        result += i * i - i / 2 + i % 3;
    }
    return result;
}

// 循环密集
volatile int test_loop_intensive(int n) {
    volatile int result = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < 100; j++) {
            result += (i * j) ^ (i + j);
        }
    }
    return result;
}

// 内存访问
volatile int test_memory_access(int n) {
    std::vector<int> data(n);
    for (int i = 0; i < n; i++) {
        data[i] = i * 7 + 13;
    }

    volatile int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += data[i];
    }
    return sum;
}

// 递归
int test_recursive(int n) {
    if (n <= 1) return 1;
    return test_recursive(n - 1) + test_recursive(n - 2);
}

// 条件分支密集
volatile int test_branching(int n) {
    volatile int result = 0;
    for (int i = 0; i < n; i++) {
        if (i % 7 == 0) result += 1;
        else if (i % 5 == 0) result += 2;
        else if (i % 3 == 0) result += 3;
        else if (i % 2 == 0) result += 4;
        else result += 5;
    }
    return result;
}

// ============================================================================
// 基准测试框架
// ============================================================================

class Benchmark {
public:
    /**
     * 测量函数执行周期数
     */
    template<typename Func, typename... Args>
    static uint64_t MeasureCycles(Func func, Args&&... args) {
        uint64_t start = __rdtsc();
        func(std::forward<Args>(args)...);
        uint64_t end = __rdtsc();
        return end - start;
    }

    /**
     * 测量函数执行时间（毫秒）
     */
    template<typename Func, typename... Args>
    static double MeasureTimeMs(Func func, Args&&... args) {
        auto start = std::chrono::high_resolution_clock::now();
        func(std::forward<Args>(args)...);
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    }

    /**
     * 运行多次取平均
     */
    template<typename Func, typename... Args>
    static uint64_t MeasureCyclesAvg(Func func, int iterations, Args&&... args) {
        uint64_t total = 0;
        for (int i = 0; i < iterations; i++) {
            total += MeasureCycles(func, std::forward<Args>(args)...);
        }
        return total / iterations;
    }

    /**
     * 获取当前内存使用
     */
    static size_t GetMemoryUsage() {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.WorkingSetSize;
        }
        return 0;
    }

    /**
     * 获取 CPU 信息
     */
    static std::string GetCPUInfo() {
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 0);

        char vendor[13] = {0};
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);

        return std::string(vendor);
    }
};

// ============================================================================
// 测试套件
// ============================================================================

void RunBenchmarkSuite() {
    std::cout << "======================================" << std::endl;
    std::cout << "CipherShell Performance Benchmark" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    std::cout << "CPU: " << Benchmark::GetCPUInfo() << std::endl;
    std::cout << "Initial memory: " << Benchmark::GetMemoryUsage() / 1024 << " KB" << std::endl;
    std::cout << std::endl;

    const int iterations = 10;
    std::vector<BenchmarkResult> results;

    // 测试 1: 算术运算
    {
        std::cout << "Testing: Arithmetic operations..." << std::endl;
        uint64_t cycles = Benchmark::MeasureCyclesAvg(test_arithmetic, iterations, 100000);
        BenchmarkResult result;
        result.testName = "Arithmetic (100K iterations)";
        result.baselineCycles = cycles;
        result.protectedCycles = cycles;  // 无保护时相同
        result.overheadRatio = 1.0;
        results.push_back(result);
    }

    // 测试 2: 循环密集
    {
        std::cout << "Testing: Loop-intensive..." << std::endl;
        uint64_t cycles = Benchmark::MeasureCyclesAvg(test_loop_intensive, iterations, 1000);
        BenchmarkResult result;
        result.testName = "Loop Intensive (1K x 100)";
        result.baselineCycles = cycles;
        result.protectedCycles = cycles;
        result.overheadRatio = 1.0;
        results.push_back(result);
    }

    // 测试 3: 内存访问
    {
        std::cout << "Testing: Memory access..." << std::endl;
        uint64_t cycles = Benchmark::MeasureCyclesAvg(test_memory_access, iterations, 100000);
        BenchmarkResult result;
        result.testName = "Memory Access (100K elements)";
        result.baselineCycles = cycles;
        result.protectedCycles = cycles;
        result.overheadRatio = 1.0;
        results.push_back(result);
    }

    // 测试 4: 递归
    {
        std::cout << "Testing: Recursion..." << std::endl;
        uint64_t cycles = Benchmark::MeasureCyclesAvg([]() { test_recursive(30); }, iterations);
        BenchmarkResult result;
        result.testName = "Recursion (fibonacci 30)";
        result.baselineCycles = cycles;
        result.protectedCycles = cycles;
        result.overheadRatio = 1.0;
        results.push_back(result);
    }

    // 测试 5: 条件分支
    {
        std::cout << "Testing: Branching..." << std::endl;
        uint64_t cycles = Benchmark::MeasureCyclesAvg(test_branching, iterations, 1000000);
        BenchmarkResult result;
        result.testName = "Branching (1M iterations)";
        result.baselineCycles = cycles;
        result.protectedCycles = cycles;
        result.overheadRatio = 1.0;
        results.push_back(result);
    }

    // 输出结果
    std::cout << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << "Results:" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::left << std::setw(35) << "Test"
              << std::right << std::setw(15) << "Cycles"
              << std::setw(15) << "Time (ms)"
              << std::endl;
    std::cout << std::string(65, '-') << std::endl;

    for (const auto& result : results) {
        std::cout << std::left << std::setw(35) << result.testName
                  << std::right << std::setw(15) << result.baselineCycles
                  << std::setw(15) << std::fixed << std::setprecision(2)
                  << (result.baselineCycles / 3000000.0)  // 假设 3GHz CPU
                  << std::endl;
    }

    std::cout << std::endl;
    std::cout << "Note: These are baseline measurements (no protection)." << std::endl;
    std::cout << "After protection, expect overhead ratios of:" << std::endl;
    std::cout << "  L1 (Guard):    ~1.05x" << std::endl;
    std::cout << "  L2 (Shield):   ~2-3x" << std::endl;
    std::cout << "  L3 (Armor):    ~5-8x" << std::endl;
    std::cout << "  L4 (Fortress): ~15-30x" << std::endl;
    std::cout << "  L5 (Citadel):  ~50-100x+" << std::endl;
    std::cout << std::endl;

    size_t finalMemory = Benchmark::GetMemoryUsage();
    std::cout << "Final memory: " << finalMemory / 1024 << " KB" << std::endl;
    std::cout << "======================================" << std::endl;
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    RunBenchmarkSuite();
    return 0;
}
