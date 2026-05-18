// Well, thanks ChatGPT for writing this clean logger for me.
#ifndef LOGGING_H
#define LOGGING_H

#include <chrono>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <vector>

// Color helpers: only emit ANSI codes when stdout is a terminal
inline const char* color_green() { return isatty(fileno(stdout)) ? "\033[1;32m" : ""; }
inline const char* color_red()   { return isatty(fileno(stdout)) ? "\033[1;31m" : ""; }
inline const char* color_reset() { return isatty(fileno(stdout)) ? "\033[0m"    : ""; }

// print for debug. Easily turn on/off by defining _DEBUG
#ifdef _DEBUG
#define DEBUG_PRINT(s) std::cout << s << std::endl;
#endif

#ifdef _BENCHMARK
#define DEBUG_PRINT(s) ; // do nothing
#endif

#define BENCH_PRINT(s) std::cout << s << std::endl;
#define PRINT_BAR                                                              \
  BENCH_PRINT("==============================================================" \
              "================");

// Default warmup iterations; can be changed at runtime via TimerLogger::setWarmup()
inline std::size_t WARMUP_ITERATIONS = 3;

// predefine some name for logging
#define CORE_TIME "Core"
#define FST_DIM_PREP "First dim prep"
#define FST_DIM_TIME "First dim"
#define OTHER_DIM_TIME "Other dim"
#define EXPAND_TIME "Expand"
#define APPLY_GALOIS "Apply Galois"
// Sub-phases of one apply-galois call, summed across all calls in an experiment.
#define APPLY_GAL_SIGMA     "  AG sigma"
#define APPLY_GAL_DECOMP    "  AG decomp"
#define APPLY_GAL_NTT_FWD   "  AG NTT fwd"
#define APPLY_GAL_NTT_INV   "  AG NTT inv"
#define APPLY_GAL_POINTWISE "  AG pointwise"
#define CONVERT_TIME "Convert"
#define CONVERT_EXTERN "Convert external product"
#define SERVER_TOT_TIME "Server total"
#define CLIENT_TOT_TIME "Client total"
#define OTHER_DIM_ADD_SUB "Other dim add/sub"
#define OTHER_DIM_MUX_EXTERN "External product in other dim"
#define DECOMP_RLWE_TIME "Decomp RLWE (including conversion)"
#define EXTERN_PROD_MAT_MULT_TIME "External product mat mult (including conversion)"
#define FST_NTT_TIME "First dim NTT"
#define EXTERN_NTT_TIME "External NTT"
#define OTHER_DIM_INTT "Other dim INTT"
#define EXTERN_COMPOSE "external compose"
#define EXTERN_DECOMP "external decompose"
#define MOD_SWITCH "Modulus switching"

// QTG (query_to_gsw) specific logging keys
#define QTG_DECOMP_RLWE_TIME "QTG Decomp RLWE"
#define QTG_EXTERN_PROD_MAT_MULT_TIME "QTG ExtProdMatMult"
#define QTG_EXTERN_COMPOSE "QTG ExtCompose"
#define QTG_EXTERN_NTT_TIME "QTG ExtNTT"
#define QTG_RIGHT_SHIFT_TIME "QTG RightShift"
#define QTG_EXTERN_DECOMP "QTG ExtDecomp"

// ODM (other_dim_mux) specific logging keys
#define ODM_DECOMP_RLWE_TIME "ODM Decomp RLWE"
#define ODM_EXTERN_PROD_MAT_MULT_TIME "ODM ExtProdMatMult"
#define ODM_EXTERN_COMPOSE "ODM ExtCompose"
#define ODM_EXTERN_NTT_TIME "ODM ExtNTT"
#define ODM_RIGHT_SHIFT_TIME "ODM RightShift"
#define ODM_EXTERN_DECOMP "ODM ExtDecomp"

#define RIGHT_SHIFT_TIME "Right shift"
#define FST_INTER_TO_CTS_TIME "First dim gather+intt"

// Enum to specify the logging context for detailed operations
enum class LogContext {
    GENERIC,        // Default generic logging
    QUERY_TO_GSW,   // Operations within query_to_gsw
    OTHER_DIM_MUX   // Operations within other_dim_mux
};

// Keys used by external_product / decomp_* / decomp_to_ntt, indexed by
// LogContext. Centralizes the if/else-on-context dispatch so callers just do
//   const auto& k = ext_log_keys(context);
//   TIME_START(k.decomp);
struct ExtLogKeys {
  const char* decomp;          // decomp_rlwe wrapper
  const char* matmul;          // extern product matmul
  const char* compose;         // CRT compose (MP path)
  const char* right_shift;     // right-shift step (MP / single-mod path)
  const char* decomp_inner;    // decompose_mp_to_rns / per-limb decomp
  const char* ntt;             // decomp_to_ntt
};

inline const ExtLogKeys& ext_log_keys(LogContext c) {
  static constexpr ExtLogKeys QTG{
      QTG_DECOMP_RLWE_TIME, QTG_EXTERN_PROD_MAT_MULT_TIME,
      QTG_EXTERN_COMPOSE,   QTG_RIGHT_SHIFT_TIME,
      QTG_EXTERN_DECOMP,    QTG_EXTERN_NTT_TIME};
  static constexpr ExtLogKeys ODM{
      ODM_DECOMP_RLWE_TIME, ODM_EXTERN_PROD_MAT_MULT_TIME,
      ODM_EXTERN_COMPOSE,   ODM_RIGHT_SHIFT_TIME,
      ODM_EXTERN_DECOMP,    ODM_EXTERN_NTT_TIME};
  static constexpr ExtLogKeys GEN{
      DECOMP_RLWE_TIME, EXTERN_PROD_MAT_MULT_TIME,
      EXTERN_COMPOSE,   RIGHT_SHIFT_TIME,
      EXTERN_DECOMP,    EXTERN_NTT_TIME};
  switch (c) {
    case LogContext::QUERY_TO_GSW:  return QTG;
    case LogContext::OTHER_DIM_MUX: return ODM;
    default:                        return GEN;
  }
}

// Hierarchical structure for pretty result
// Map structure: Parent -> Children
const std::unordered_map<std::string, std::vector<std::string>> LOG_HIERARCHY = {
    {SERVER_TOT_TIME, {EXPAND_TIME, CONVERT_TIME, FST_DIM_TIME, OTHER_DIM_TIME, MOD_SWITCH}},
    {EXPAND_TIME, {APPLY_GALOIS}},
    {APPLY_GALOIS, {APPLY_GAL_SIGMA, APPLY_GAL_DECOMP, APPLY_GAL_NTT_FWD, APPLY_GAL_NTT_INV, APPLY_GAL_POINTWISE}},
    {CONVERT_TIME, {CONVERT_EXTERN}},
    {CONVERT_EXTERN, {QTG_DECOMP_RLWE_TIME, QTG_EXTERN_NTT_TIME, QTG_EXTERN_PROD_MAT_MULT_TIME}}, // Children for QTG path
    {QTG_DECOMP_RLWE_TIME, {QTG_EXTERN_COMPOSE, QTG_RIGHT_SHIFT_TIME, QTG_EXTERN_DECOMP}},
    {FST_DIM_TIME, {CORE_TIME, FST_DIM_PREP, FST_INTER_TO_CTS_TIME, FST_NTT_TIME}},
    {OTHER_DIM_TIME, {OTHER_DIM_MUX_EXTERN, OTHER_DIM_INTT, OTHER_DIM_ADD_SUB}},
    {OTHER_DIM_MUX_EXTERN, {ODM_DECOMP_RLWE_TIME, ODM_EXTERN_NTT_TIME, ODM_EXTERN_PROD_MAT_MULT_TIME}}, // Replaced children with ODM specific
    {ODM_DECOMP_RLWE_TIME, {ODM_EXTERN_COMPOSE, ODM_RIGHT_SHIFT_TIME, ODM_EXTERN_DECOMP}},
    {DECOMP_RLWE_TIME, {EXTERN_COMPOSE, EXTERN_NTT_TIME, RIGHT_SHIFT_TIME, EXTERN_DECOMP}} // Generic fallback
};



class TimerLogger {
private:
  // Stores start times of active sections
  std::unordered_map<std::string, std::chrono::high_resolution_clock::time_point> startTimes;

  // One-time timers: start/result stored here, printed on demand
  std::unordered_map<std::string, std::chrono::high_resolution_clock::time_point> onceStartTimes_;
  std::unordered_map<std::string, double> onceTimes_;

  // Stores all timing results for multiple experiments
  std::vector<std::unordered_map<std::string, double>> experimentRecords;

  // Stores timing data for the current experiment
  std::unordered_map<std::string, double> currentExperiment;

  // Private constructor for Singleton
  TimerLogger() = default;

  // Recursive helper for pretty printing
  void prettyPrintHelper(
      const std::string &section, const std::string &prefix, bool isLast,
      const std::unordered_map<std::string, double> &avgTimes) const;

public:
  // Singleton instance
  static TimerLogger &getInstance();

  // Start logging time for a section
  void start(const std::string &sectionName);

  // Stop logging time for a section
  void end(const std::string &sectionName);

  // One-time timers: measure a block once and print immediately on end.
  // Safe to call repeatedly inside a loop — durations are summed.
  void startOnce(const std::string &sectionName);
  void endOnce(const std::string &sectionName);
  void printOnce(const std::string &sectionName) const;

  // End the current experiment and start a new one
  void endExperiment();

  // Print results for specific experiment. -1 to print all experiments
  void printResults(int expId = -1);

  // Compute and print average time across experiments
  void printAverageResults();

  double getAvgTime(const std::string &sectionName);

  // Get timing from the last recorded experiment (ignores warmup logic)
  double getLastTime(const std::string &sectionName);

  // Pretty print hierarchical results
  void prettyPrint();

  void cleanup();

  static void setWarmup(std::size_t n) { WARMUP_ITERATIONS = n; }

  // Prevent copying
  TimerLogger(const TimerLogger &) = delete;
  TimerLogger &operator=(const TimerLogger &) = delete;
};

// Macros for easy time logging
#define TIME_START(sec) TimerLogger::getInstance().start(sec)
#define TIME_END(sec) TimerLogger::getInstance().end(sec)
#define END_EXPERIMENT() TimerLogger::getInstance().endExperiment()
#define PRINT_RESULTS(expId) TimerLogger::getInstance().printResults(expId)
#define PRINT_AVERAGE_RESULTS() TimerLogger::getInstance().printAverageResults()
#define GET_AVG_TIME(sec) TimerLogger::getInstance().getAvgTime(sec)
#define GET_LAST_TIME(sec) TimerLogger::getInstance().getLastTime(sec)
#define PRETTY_PRINT() TimerLogger::getInstance().prettyPrint()
#define CLEAN_TIMER() TimerLogger::getInstance().cleanup()

// One-time timing macros: accumulate across loop iterations, print on TIME_ONCE_END.
#define TIME_ONCE_START(sec)       TimerLogger::getInstance().startOnce(sec)
#define TIME_ONCE_END(sec)         TimerLogger::getInstance().endOnce(sec)
#define PRINT_ONCE(sec)            TimerLogger::getInstance().printOnce(sec)

#endif // LOGGER_H
