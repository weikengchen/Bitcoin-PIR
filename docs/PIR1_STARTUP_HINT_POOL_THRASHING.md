# pir1 startup: concurrent hint-pool thrashing starves OnionPIR worker

**Status:** root cause identified 2026-05-15 after a long debugging session.
This is **not** a code bug in OnionPIRv2 (the earlier
`UPSTREAM_REQUEST_2402b16_REGRESSION.md` filed against the upstream
agent is a false alarm — withdraw it). The symptom is a deployment
ordering issue specific to pir1's single-host configuration.

**TL;DR:** Both `pir-primary.service` and `pir-secondary.service`
auto-start at boot. Each launches with `--pool-size 8` and starts
generating HarmonyPIR V2 hint-pool entries in parallel rayon
workers. Combined, the two processes burst the 6-core
i7-8700 to **1172% CPU (709% + 463%)** with load average ≥ 16,
saturating every logical core for ~2 minutes. During that window,
the OnionPIR mpsc-served worker thread (one OS thread per database)
gets only sporadic time slices — a 7 ms `KeyStore::set_galois_keys`
call balloons to 60–190 s of wall time as the kernel scheduler
rotates through 200+ runnable threads.

Once the worker finally completes registration, the *subsequent*
`Server::answer_query` calls also struggle: each query goes through
many short critical sections (touch+lookup+expand+matmul) that
each get interrupted, and the C++ `try/catch` swallows exceptions
on partial progress — producing empty `Vec`s for all 150 INDEX
queries.

Workaround (pick one):

1. **Wait ~3 min after restart before connecting.** This is what
   the earlier successful smoke test (05:14 CET startup → 05:18
   client connect → 7 ms registration) inadvertently did.
2. **Stagger the systemd startups** so pir-secondary's hint-pool
   completes before pir-primary's begins (or vice-versa). Add
   `After=pir-secondary.service` to `pir-primary.service` and a
   short `ExecStartPre=/bin/sleep 60` to one of them.
3. **Reduce hint-pool concurrency.** Lower `--pool-size` or run
   only one of {primary, secondary} with `--serve-hints`. pir1 is
   a single-host dev/demo box; the two services don't actually
   need to both pre-populate hint pools simultaneously.

---

## 1. Reproduction (today's pir1)

* Server `pir-primary` started at 09:00:22 CET
  (`unified_server --port 8091 --role primary --serve-hints --serve-queries --pool-size 8 --pool-dir /home/pir/data/hint-pool ...`)
* Server `pir-secondary` started simultaneously
  (`unified_server --port 8092 --role secondary --serve-hints --serve-queries --pool-size 8 ...`)
* OnionPIR ready at 09:00:22
* Client connects at 09:00:35 (13 s after startup, during hint-pool generation)
* RegisterKeys timing on the worker thread:
  ```
  09:01:54 client 1 keys registered in 79.79s
  ```
* Per-thread CPU breakdown via `ps -p $PID -L`: 12 unified_server
  worker threads at 13–24 % CPU each, all in futex_ state. Total
  ≈ 200 % CPU just from pir-primary, plus equal from pir-secondary.
  System load average sustained at 15+ for several minutes.

## 2. Earlier successful runs (for comparison)

* 05:14:25 CET pir-primary started
* 05:14:48 - 05:17:27 hint-pool generated 8 entries (sequential, each ~22 s)
* **No client connected** during this window
* 05:18:14 (51 s AFTER hint-pool done) client 3 connects
* Registration: **7.43 ms** ✓

The successful run "got lucky" — the smoke test happened to be
fired off after hint-pool warmup completed. The failing runs all
ran the smoke test immediately after restart.

## 3. What made me chase a phantom upstream bug

When I bumped onionpir to 2402b16 + applied
`.par_iter_mut()` in `unified_server.rs::AnswerBatch`, the timing
showed a NEW symptom: registration ~100 s + every answer_query
empty. I attributed both to the rev bump. I then rolled back to
fb14f4e, and the SAME pattern persisted. I attributed it to
2402b16 cache poisoning. After a clean rebuild and even a full
reboot of pir1, the pattern STILL persisted, until I noticed the
two unified_server processes were maxing out the CPU together.

Once I correlated the slow registration with high system load
(both processes running hint-pool concurrently), the picture
clicked. The earlier "fast registration" runs happened to be
on idle servers; the "slow" runs happened on saturated ones.

## 4. Recommended fix (pick lowest-risk)

Quick win: edit `/etc/systemd/system/pir-secondary.service` to
add `ExecStartPre=/bin/sleep 60`. pir-primary starts first; its
hint-pool gets 60 s of CPU alone; pir-secondary then kicks in.
Either is done by ~1.5 min after boot, and any client connecting
later has the CPU to itself.

Long-term: roll the hint-pool generation off of rayon's default
global pool onto a dedicated low-priority thread pool with `nice
+10` or `SCHED_BATCH`. The OnionPIR mpsc worker thread runs at
the default nice level and would always preempt the hint-pool
work. This requires a `harmonypir` crate change (or a wrapper in
`unified_server.rs`'s hint-pool spawn site).

## 5. Withdraw the upstream bug report

`docs/UPSTREAM_REQUEST_2402b16_REGRESSION.md` was filed against
the OnionPIRv2 agent at SHA f4fe3b76. Add a follow-up commit
labeling it superseded by this doc — the 2402b16 patch is sound;
the regression I observed was a deployment ordering issue, not
a thread-safety regression in OnionPIRv2.

The earlier
`UPSTREAM_REQUEST_THREAD_SAFETY.md` (which produced the
landed 2402b16 patch) remains valid — it solved a real future
hazard for parallel `answer_query` even if we haven't deployed
the BitcoinPIR-side rayon switch yet.
