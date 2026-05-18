#include "tests.h"
#include <fstream>

void PirTest::print_cpu_info() {
  print_func_name(__FUNCTION__);

  PRINT_BAR;
  BENCH_PRINT("CPU Information:");
  PRINT_BAR;

  // Get CPU model name
  std::ifstream cpuinfo("/proc/cpuinfo");
  std::string line;
  std::string model_name;
  std::string vendor_id;
  int cpu_count = 0;

  if (cpuinfo.is_open()) {
    while (std::getline(cpuinfo, line)) {
      if (line.find("model name") != std::string::npos) {
        model_name = line.substr(line.find(":") + 2);
        break;
      }
      if (line.find("vendor_id") != std::string::npos) {
        vendor_id = line.substr(line.find(":") + 2);
      }
      if (line.find("processor") != std::string::npos) {
        cpu_count++;
      }
    }
    cpuinfo.close();
  }

  BENCH_PRINT("Vendor ID: " << vendor_id);
  BENCH_PRINT("Model Name: " << model_name);
  BENCH_PRINT("CPU Count: " << cpu_count);

  // Get additional CPU information using lscpu
  BENCH_PRINT("\nDetailed CPU Information:");
  system("lscpu | grep -E 'Model name|Architecture|CPU op-mode|Thread|Core|Socket|NUMA|L1d|L1i|L2|L3'");

  // Get memory information
  BENCH_PRINT("\nMemory Information:");
  system("free -h");

  // Get cache information
  BENCH_PRINT("\nCache Information:");
  system("lscpu | grep -E 'L1d|L1i|L2|L3'");

  // Get CPU flags (instruction sets)
  BENCH_PRINT("\nCPU Flags (Instruction Sets):");
  system("lscpu | grep -E 'Flags|avx|sse|fma'");

  PRINT_BAR;
}
