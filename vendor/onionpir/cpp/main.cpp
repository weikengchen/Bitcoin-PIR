#include "tests.h"
#include <cstring>
#include <cstdlib>
#include <string>

int main(int argc, char *argv[]) {
  std::string test_name = "pir";
  size_t num_experiments = 10;
  size_t warmup = 3;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--test") == 0 && i + 1 < argc) {
      test_name = argv[++i];
    } else if (strcmp(argv[i], "--experiments") == 0 && i + 1 < argc) {
      num_experiments = std::atoi(argv[++i]);
    } else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
      warmup = std::atoi(argv[++i]);
    }
  }

  TimerLogger::setWarmup(warmup);

  PirTest test;
  test.num_experiments = num_experiments + warmup;
  test.run_test(test_name);
  return 0;
}