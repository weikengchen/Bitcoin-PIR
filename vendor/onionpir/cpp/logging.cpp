#include "logging.h"
#include <iostream>

// Per-thread instance getter.
//
// Was `static TimerLogger instance` — but the macros (TIME_START / TIME_END
// etc., 36 hits per answer_query in server.cpp) mutate the logger's
// unordered_map state on every call, racing under parallel answer_query
// from rayon-style downstream consumers. `thread_local` keeps each thread's
// timings isolated. The PRETTY_PRINT()/PRINT_AVERAGE_RESULTS() debug
// helpers only see the calling thread's timings — that's fine because
// the test harness calls them from the main thread (same thread that
// drove the experiments).
TimerLogger &TimerLogger::getInstance() {
  thread_local TimerLogger instance;
  return instance;
}

// Start logging time for a section
void TimerLogger::start(const std::string &sectionName) {
  startTimes[sectionName] = std::chrono::high_resolution_clock::now();
}

// Stop logging time for a section
void TimerLogger::end(const std::string &sectionName) {
  auto it = startTimes.find(sectionName);
  if (it != startTimes.end()) {
    double duration =
        std::chrono::duration<double, std::milli>(
            std::chrono::high_resolution_clock::now() - it->second)
            .count();
    currentExperiment[sectionName] += duration;
    startTimes.erase(it);
  }
}

// End the current experiment and store the results
void TimerLogger::endExperiment() {
  experimentRecords.push_back(currentExperiment);
  currentExperiment.clear(); // Reset for the next experiment
}

// Print timing results for a specific experiment or all experiments
void TimerLogger::printResults(int expId) {
  if (experimentRecords.empty()) {
    std::cout << "No experiments recorded.\n";
    return;
  }

  if (expId == -1) {
    // Print all experiments
    std::cout << "========================== Experiment Timing Results "
                 "=========================\n";
    for (size_t i = 0; i < experimentRecords.size(); ++i) {
      std::cout << "Experiment " << i + 1 << ":\n";
      for (const auto &[section, time] : experimentRecords[i]) {
        std::cout << "  " << section << ": " << time << " ms\n";
      }
    }
  } else if (expId >= 1 && expId <= experimentRecords.size()) {
    // Print a specific experiment
    std::cout << "========================== Experiment " << expId
              << " Timing Results =========================\n";
    for (const auto &[section, time] : experimentRecords[expId - 1]) {
      std::cout << section << ": " << time << " ms\n";
    }
  } else {
    std::cout << "Invalid experiment index. Please choose between 1 and "
              << experimentRecords.size() << ".\n";
  }
}

// Compute and print average timing results across experiments
void TimerLogger::printAverageResults() {
  if (experimentRecords.size() <= WARMUP_ITERATIONS) {
    std::cout << "Not enough experiments to compute post-warm-up averages ("
              << experimentRecords.size() << " recorded, " << WARMUP_ITERATIONS
              << " warm-ups).\n";
    return;
  }

  std::unordered_map<std::string, double> totalTimes;
  std::unordered_map<std::string, int> count;

  // start from WARMUP_ITERATIONS, not 0
  for (std::size_t idx = WARMUP_ITERATIONS; idx < experimentRecords.size();
       ++idx) {
    for (const auto &[section, time] : experimentRecords[idx]) {
      totalTimes[section] += time;
      count[section] += 1;
    }
  }

  std::cout << "===== Average Timing Results (after first " << WARMUP_ITERATIONS
            << " warm-up runs) =====\n";
  for (const auto &[section, totalTime] : totalTimes) {
    double avgTime = totalTime / count[section];
    std::cout << section << ": " << static_cast<std::size_t>(avgTime)
              << " ms\n";
  }
}

double TimerLogger::getAvgTime(const std::string &sectionName) {
  if (experimentRecords.size() <= WARMUP_ITERATIONS)
    return 0.0;

  double sum = 0.0;
  std::size_t validRuns = 0;

  for (std::size_t idx = WARMUP_ITERATIONS; idx < experimentRecords.size(); ++idx) {
    auto it = experimentRecords[idx].find(sectionName);
    if (it != experimentRecords[idx].end()) {
      sum += it->second;
      ++validRuns;
    }
  }
  return validRuns ? sum / validRuns : 0.0;
}

double TimerLogger::getLastTime(const std::string &sectionName) {
  if (experimentRecords.empty())
    return 0.0;
  auto &last = experimentRecords.back();
  auto it = last.find(sectionName);
  return (it != last.end()) ? it->second : 0.0;
}

void TimerLogger::prettyPrintHelper(
    const std::string &section, const std::string &prefix, bool isLast,
    const std::unordered_map<std::string, double> &avgTimes) const {
  auto it = avgTimes.find(section);
  if (it != avgTimes.end()) {
    std::cout << prefix << (isLast ? "└── " : "├── ") << section << ": "
              << static_cast<std::size_t>(it->second) << " ms\n";
  }

  auto sub = LOG_HIERARCHY.find(section);
  if (sub != LOG_HIERARCHY.end()) {
    std::size_t n = sub->second.size();
    for (std::size_t i = 0; i < n; ++i) {
      prettyPrintHelper(sub->second[i], prefix + (isLast ? "    " : "│   "),
                        i == n - 1, avgTimes);
    }
  }
}

// 2) ---- recompute averages (skipping warm-ups) and pass to helper ----
void TimerLogger::prettyPrint() {
  if (experimentRecords.size() <= WARMUP_ITERATIONS) {
    std::cout << "Not enough experiments to compute post-warm-up averages ("
              << experimentRecords.size() << " recorded, " << WARMUP_ITERATIONS
              << " warm-ups).\n";
    return;
  }

  // -------- build the map of average times (post-warm-up only) --------
  std::unordered_map<std::string, double> totals;
  std::unordered_map<std::string, int> counts;

  for (std::size_t idx = WARMUP_ITERATIONS; idx < experimentRecords.size();
       ++idx) {
    for (const auto &[section, t] : experimentRecords[idx]) {
      totals[section] += t;
      counts[section] += 1;
    }
  }

  std::unordered_map<std::string, double> averages;
  for (const auto &[section, total] : totals) {
    averages[section] = total / counts[section];
  }

  // ------------------ offline section ------------------
  std::cout << "========== Offline Setup ==========\n";
  auto ntt_it = onceTimes_.find("DB NTT + realign");
  if (ntt_it != onceTimes_.end()) {
    std::cout << "  DB NTT + realign: " << static_cast<std::size_t>(ntt_it->second) << " ms" << std::endl;
  }

  // ------------------ online section ------------------
  std::cout << "========== Online Average Results (after first " << WARMUP_ITERATIONS
            << " warm-up runs) ==========\n";
  prettyPrintHelper(SERVER_TOT_TIME, "", false, averages);
  prettyPrintHelper(CLIENT_TOT_TIME, "", true, averages);
}

void TimerLogger::startOnce(const std::string &sectionName) {
  onceStartTimes_[sectionName] = std::chrono::high_resolution_clock::now();
}

void TimerLogger::endOnce(const std::string &sectionName) {
  auto it = onceStartTimes_.find(sectionName);
  if (it != onceStartTimes_.end()) {
    onceTimes_[sectionName] = std::chrono::duration<double, std::milli>(
                                  std::chrono::high_resolution_clock::now() - it->second)
                                  .count();
    onceStartTimes_.erase(it);
  }
}

void TimerLogger::printOnce(const std::string &sectionName) const {
  auto it = onceTimes_.find(sectionName);
  if (it != onceTimes_.end()) {
    std::cout << sectionName << ": " << static_cast<std::size_t>(it->second) << " ms\n";
  }
}


void TimerLogger::cleanup() {
    startTimes.clear();
    experimentRecords.clear();
    currentExperiment.clear();
    onceStartTimes_.clear();
    onceTimes_.clear();
}