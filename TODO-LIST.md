# MMT-Probe Remediation TODO List

**Last Updated:** November 17, 2025
**Status:** 0/89 items completed (0%)

This checklist tracks all remediation items identified in the comprehensive C/C++ audit report. Items are organized by priority and category for systematic implementation tracking.

---

## 📊 Progress Summary

| Priority | Total | Completed | Remaining | Percentage |
|----------|-------|-----------|-----------|------------|
| **P0 - CRITICAL (Week 1)** | 8 | 0 | 8 | 0% |
| **P1 - HIGH (Weeks 2-4)** | 15 | 0 | 15 | 0% |
| **P2 - MEDIUM (Months 1-2)** | 28 | 0 | 28 | 0% |
| **P3 - LOW (Months 3-6)** | 38 | 0 | 38 | 0% |
| **TOTAL** | **89** | **0** | **89** | **0%** |

---

## 🔴 P0 - CRITICAL PRIORITY (Week 1)

### Security Vulnerabilities (Must Fix IMMEDIATELY)

- [ ] **V1: Fix buffer overflow in socket_output.c:86**
  - File: `src/modules/output/socket/socket_output.c`
  - Replace `strcpy(sa_un.sun_path, socket_descriptor)` with bounds-checked `strncpy`
  - Add validation: `if (strlen(socket_descriptor) >= sizeof(sa_un.sun_path))`
  - Ensure null termination
  - **CWE-120, CVSS 9.8**

- [ ] **V2: Fix integer overflow in license.c:124 (MAC count)**
  - File: `src/modules/license/license.c`
  - Replace `atoi()` with `strtol()` and validate result
  - Check overflow before multiplication: `if (mac_count > SIZE_MAX / 12)`
  - Add bounds check: `mac_count_raw < 0 || mac_count_raw > 1000`
  - **CWE-190, CVSS 7.5**

- [ ] **V3: Fix integer overflow in license.c:137 (date calculation)**
  - File: `src/modules/license/license.c`
  - Validate date components with `strtol()` instead of `atoi()`
  - Add range checks: year (2000-2100), month (1-12), day (1-31)
  - Check for multiplication overflow
  - **CWE-190, CVSS 7.5**

- [ ] **V5: Fix input validation in configure.c:112**
  - File: `src/configure.c`
  - Replace unbounded `atoi(optarg)` with `strtol()` and range validation
  - Add error handling for invalid input
  - Validate all command-line numeric arguments
  - **CWE-20, HIGH**

- [ ] **V5b: Fix input validation in configure.c:735-850 (_parse_operator)**
  - File: `src/configure.c`
  - Add bounds checking before `strcpy(op->attribute, token)`
  - Use `strncpy()` with size validation
  - Validate token length against ATTRIBUTE_MAX_SIZE
  - **CWE-20, HIGH**

### Performance Critical Fixes

- [ ] **P1: Optimize hash table load factor (hash.c:144-146)**
  - File: `src/lib/hash.c`
  - Change rehash trigger from 100% to 75% capacity
  - Update condition: `if (h->count >= (h->capability * 3) / 4)`
  - Test with high-load scenarios
  - **Expected: 50-70% latency improvement**

- [ ] **P2: Replace LPI 512MB bit array with sparse structure (lpi.c:137)**
  - File: `src/modules/lpi/lpi.c`
  - Replace `bit_create(0x100000000)` with hash set or two-level array
  - Implement sparse_ip_set_t or sparse_bit_array_t
  - Add LRU eviction for bounded memory
  - **Expected: 99% memory reduction (512MB → 1-10MB)**

- [ ] **P3: Remove nanosleep from PCAP capture hot path**
  - Files: `src/modules/packet_capture/pcap/pcap_capture.c:166, 232, 541`
  - Replace `nanosleep(100000L)` with pthread condition variables
  - Implement event-driven ring buffer signaling
  - Add `pthread_cond_wait()` / `pthread_cond_signal()`
  - **Expected: 20-30% throughput increase, 50-100μs latency reduction**

---

## 🟠 P1 - HIGH PRIORITY (Weeks 2-4)

### Security Fixes

- [ ] **V6: Fix TOCTOU race condition in mmt_bus.c:108-128**
  - File: `src/modules/dynamic_conf/mmt_bus.c`
  - Move `is_waiting` check inside mutex lock
  - Ensure atomic check-and-signal operation
  - **CWE-367, MEDIUM**

- [ ] **V7: Add resource limits to query_based_report.c:187**
  - File: `src/modules/dpi/report/query_based_report.c`
  - Add `MAX_QUERY_ENTRIES` limit (100,000)
  - Check hash table size before adding entries
  - Log warning when limit reached
  - **CWE-770, MEDIUM**

- [ ] **V8: Add NULL checks in pcap_capture.c:225**
  - File: `src/modules/packet_capture/pcap/pcap_capture.c`
  - Add defense-in-depth NULL check after allocation
  - Handle allocation failure gracefully
  - **CWE-476, MEDIUM**

- [ ] **V9: Replace strdup pattern in http_reconstruct.c:528, 550**
  - File: `src/modules/dpi/reconstruct/http/http_reconstruct.c`
  - Use standard `strdup()` instead of manual `malloc + strcpy`
  - Add NULL check after strdup
  - **MEDIUM**

- [ ] **V4: Deprecate or remove _old/ directory**
  - Files: `src/_old/*` (15+ strcpy vulnerabilities)
  - Verify _old/ code is not compiled in production
  - Add `#error` directive to prevent accidental compilation
  - Document deprecation or remove entirely
  - **HIGH**

### Performance Optimizations

- [ ] **P4: Implement Robin Hood hashing or separate chaining**
  - File: `src/lib/hash.c`
  - Replace linear probing with better collision resolution
  - Consider separate chaining for simpler implementation
  - Maintain occupied items list for O(m) iteration
  - **Expected: Eliminate O(n) worst-case**

- [ ] **P5: Optimize lock-free ring with C11 atomics**
  - File: `src/modules/packet_capture/pcap/lock_free_spsc_ring.h`
  - Replace `__sync_*` with C11 `atomic_*` operations
  - Use `memory_order_acquire` / `memory_order_release`
  - Require power-of-2 ring sizes for bitwise modulo
  - Cache-align `_cached_head` and `_cached_tail`
  - **Expected: 30-50% ring operation speedup**

- [ ] **P6: Implement zero-copy or buffer pooling for PCAP**
  - File: `src/modules/packet_capture/pcap/pcap_capture.c:225`
  - Eliminate extra `memcpy()` per packet
  - Use pre-allocated buffer pool in ring
  - Implement buffer ownership transfer
  - **Expected: 10-15% packet processing improvement**

- [ ] **P7: Batch timer updates in worker.c**
  - File: `src/worker.c:163, 176, 188`
  - Update timestamps every 64 packets instead of per-packet
  - Add `TIMER_UPDATE_INTERVAL` macro
  - Reduce `gettimeofday()` call frequency
  - **Expected: 5-10% CPU utilization reduction**

- [ ] **P8: Implement per-thread LPI state**
  - File: `src/modules/lpi/lpi.c:147, 178-180`
  - Eliminate global mutex contention
  - Use thread-local storage for LPI data
  - Consider lock-free hash table
  - **Expected: Reduce mutex contention**

### Build System & Static Analysis

- [ ] **Add cppcheck to build system**
  - Create `make analyze` target
  - Add `cppcheck --enable=all src/` to CI/CD
  - Fix all reported issues

- [ ] **Add clang-tidy to build system**
  - Create `make clang-tidy` target
  - Configure checks for security and performance
  - Integrate into CI/CD pipeline

- [ ] **Enable compiler hardening flags**
  - Add `-fstack-protector-strong` to CFLAGS
  - Add `-D_FORTIFY_SOURCE=2` to CFLAGS
  - Add `-Wformat-security` to CFLAGS
  - Test build with all flags enabled

- [ ] **Add sanitizers to test builds**
  - Create `make asan` target with AddressSanitizer
  - Create `make ubsan` target with UndefinedBehaviorSanitizer
  - Create `make tsan` target with ThreadSanitizer
  - Run test suite with each sanitizer

---

## 🟡 P2 - MEDIUM PRIORITY (Months 1-2)

### Code Quality - Function Complexity

- [ ] **Refactor configure.c:_load_cfg_from_file() (238 lines)**
  - Break into smaller functions: `load_kafka_config()`, `load_redis_config()`, etc.
  - Reduce cyclomatic complexity from ~45 to <15 per function
  - Extract configuration parsing logic
  - Add unit tests for each sub-function

- [ ] **Refactor main.c:_parse_options() (128 lines)**
  - Extract option handling into separate functions
  - Reduce nesting depth from 5+ to <4 levels
  - Use switch statement or function pointer table

- [ ] **Refactor configure.c:_parse_operator() (103 lines)**
  - Simplify operator parsing logic
  - Extract validation into separate function
  - Reduce complexity to <20

- [ ] **Refactor configure.c:conf_release() (101 lines)**
  - Break into module-specific release functions
  - Ensure symmetric init/release pairing

- [ ] **Refactor main.c:_create_sub_processes() (106 lines)**
  - Extract process creation logic per process type
  - Separate error handling into helper functions

### Code Quality - Reduce Nesting Depth

- [ ] **Refactor session_report.c:200-450 (6-7 levels)**
  - File: `src/modules/dpi/report/session_report.c`
  - Use early returns (guard clauses)
  - Extract nested logic into helper functions
  - Target: <4 nesting levels

- [ ] **Refactor configure.c:250-350 (6 levels)**
  - Use guard clauses for early validation
  - Extract nested loops into functions

- [ ] **Refactor event_based_report.c:150-300 (5-6 levels)**
  - File: `src/modules/dpi/report/event_based_report.c`
  - Flatten nested conditionals
  - Use lookup tables where appropriate

### Code Quality - Reduce Duplication

- [ ] **Refactor session report modules (40-60% duplication)**
  - Create common `report_ops_t` interface
  - Extract shared patterns: `reset()`, `build_message()`, `on_session_end()`
  - Files affected:
    - `src/modules/dpi/report/session_report.c` (683 lines)
    - `src/modules/dpi/report/session_report_web.c` (313 lines)
    - `src/modules/dpi/report/session_report_ssl.c` (220 lines)
    - `src/modules/dpi/report/session_report_ftp.c` (180 lines)
    - `src/modules/dpi/report/session_report_rtp.c` (250 lines)
    - `src/modules/dpi/report/session_report_gtp.c` (190 lines)
  - **Expected: 50-70% code reduction**

- [ ] **Refactor output modules (common patterns)**
  - Create abstract `output_driver_t` interface
  - Standardize `init()`, `send()`, `close()` signatures
  - Files affected:
    - `src/modules/output/file/file_output.c` (450 lines)
    - `src/modules/output/kafka/kafka_output.c` (380 lines)
    - `src/modules/output/redis/redis.c` (520 lines)
    - `src/modules/output/mongodb/mongodb.c` (610 lines)
    - `src/modules/output/mqtt/mqtt_output.c` (290 lines)
    - `src/modules/output/socket/socket_output.c` (340 lines)
  - **Expected: Easier to add new output channels**

### Error Handling Improvements

- [ ] **Add error checking to fprintf calls**
  - File: `src/modules/output/file/file_output.c:223`
  - Check return value and handle disk-full scenarios
  - Implement error counter and disable after threshold

- [ ] **Add error checking to pthread_create calls**
  - File: `src/modules/dynamic_conf/server.c:60`
  - Check return value and log errors
  - Propagate failure to caller

- [ ] **Add error checking to pthread_mutex_init calls**
  - Search all mutex initializations
  - Validate return values
  - Handle initialization failures

- [ ] **Standardize error code conventions**
  - Document error return conventions (0 vs -1 for success)
  - Create common error code enum
  - Add error context propagation

### Documentation - Magic Numbers

- [ ] **Document worker.c:243 stack_type values (CRITICAL)**
  - Define `STACK_TYPE_FULL_DPI`, `STACK_TYPE_PASS_THROUGH`
  - Add comments explaining each mode
  - Document why 1 and 99 are special

- [ ] **Document timeout values in configure.c:159-162**
  - `tcp_short_time = 60` - explain "short" duration
  - `tcp_long_time = 600` - explain 10-minute choice
  - `udp_time = 15` - document UDP timeout rationale
  - `icmp_time = 1500` - explain 25-minute ICMP timeout

- [ ] **Define port number constants**
  - Replace magic numbers with named constants:
    - `DEFAULT_REDIS_PORT 6379` (configure.c:169)
    - `DEFAULT_KAFKA_PORT 9092` (configure.c:176)
    - `DEFAULT_MONGODB_PORT 27017` (configure.c:192)

- [ ] **Document RSS hash key bytes**
  - File: `src/modules/packet_capture/dpdk/dpdk_capture.c:57-64`
  - Explain symmetric RSS hash key (0x6D, 0x5A)
  - Reference DPDK documentation

---

## 🟢 P3 - LOW PRIORITY (Months 3-6)

### Documentation - API Documentation

- [ ] **Set up Doxygen for documentation generation**
  - Create `Doxyfile` configuration
  - Configure output directory
  - Add `make docs` target

- [ ] **Document worker.h public API**
  - Add file-level documentation
  - Document `worker_init()` with parameters and return values
  - Add usage examples
  - Document `worker_free()`, `worker_run()`, etc.

- [ ] **Document dpi.h public API**
  - File: `src/modules/dpi/dpi.h`
  - Add function documentation for all public functions
  - Document callback signatures
  - Add usage examples

- [ ] **Document configure.h public API**
  - File: `src/configure.h`
  - Document configuration structure
  - Explain configuration options
  - Add examples

- [ ] **Document output module interfaces**
  - Document common output interface patterns
  - Explain module initialization sequence
  - Add examples for each output type

- [ ] **Increase comment density to 15-25%**
  - Current: 3-8% average
  - Target files:
    - configure.c (2.9% → 15%)
    - main.c (7.6% → 15%)
    - worker.c (8.3% → 15%)
    - dpdk_capture.c (3.9% → 15%)
    - session_report.c (2.3% → 15%)

- [ ] **Document complex algorithms**
  - Hash table rehashing logic (hash.c:137)
  - TCP reassembly (src/modules/dpi/reassembly/tcp_reassembly.c)
  - Lock-free ring buffer operations
  - Packet distribution hashing

### Testing Infrastructure

- [ ] **Choose and integrate unit test framework**
  - Evaluate: Unity, Check, CMocka
  - Add to build system
  - Create `test/unit/` directory structure

- [ ] **Write unit tests for hash table**
  - Test insertion, deletion, search
  - Test rehashing behavior
  - Test collision handling
  - Test load factor triggers

- [ ] **Write unit tests for lock-free ring**
  - Test enqueue/dequeue operations
  - Test full/empty conditions
  - Test single-producer-single-consumer semantics

- [ ] **Write unit tests for configuration parsing**
  - Test valid configurations
  - Test invalid input handling
  - Test edge cases

- [ ] **Write integration tests for packet capture**
  - Test PCAP mode with sample files
  - Test DPDK mode (if available)
  - Test ring buffer overflow handling

- [ ] **Write integration tests for DPI pipeline**
  - Test end-to-end packet processing
  - Test callback invocation
  - Test session tracking

- [ ] **Add fuzzing for configuration parser**
  - Use AFL or libFuzzer
  - Fuzz configuration file parsing
  - Fuzz command-line argument parsing

- [ ] **Add fuzzing for packet parsing**
  - Fuzz PCAP file parsing
  - Fuzz protocol dissection
  - Fuzz reconstruction modules

- [ ] **Add performance benchmarks**
  - Benchmark hash table operations
  - Benchmark ring buffer throughput
  - Benchmark packet processing rate
  - Track performance over time

- [ ] **Set up CI/CD pipeline**
  - Configure GitHub Actions or GitLab CI
  - Run unit tests on every commit
  - Run static analysis on every PR
  - Run sanitizer builds nightly

- [ ] **Add code coverage tracking**
  - Use gcov/lcov or similar
  - Target 70% code coverage
  - Generate coverage reports
  - Track coverage trends

### Build System Improvements

- [ ] **Evaluate CMake migration**
  - Assess effort required
  - Create proof-of-concept CMakeLists.txt
  - Plan migration strategy

- [ ] **Create CMakeLists.txt for main project**
  - Define project structure
  - Handle module compilation options
  - Support all existing build configurations

- [ ] **Migrate module builds to CMake**
  - Convert mk/modules.mk to CMake options
  - Support PCAP vs DPDK selection
  - Support optional modules (Kafka, Redis, etc.)

- [ ] **Add CMake install targets**
  - Define installation paths
  - Install binaries and configuration files
  - Install systemd service file

- [ ] **Add build verification tests**
  - Test all module combinations compile
  - Verify no missing symbols
  - Check library dependencies

- [ ] **Improve Makefile documentation**
  - Document all build targets
  - Explain module compilation flags
  - Add examples for common builds

### Code Quality - Naming Conventions

- [ ] **Standardize return value naming**
  - Choose: `ret` vs `retval` vs `ret_val`
  - Update coding standards document
  - Refactor inconsistent usage

- [ ] **Standardize boolean naming**
  - Use `is_*` or `has_*` prefixes consistently
  - Update: `enabled`, `flag` → `is_enabled`, `has_flag`

- [ ] **Standardize count variable naming**
  - Choose: `count` vs `num` vs `nb`
  - Update coding standards document
  - Refactor inconsistent usage

- [ ] **Standardize macro naming**
  - Function-like macros: lowercase or uppercase?
  - Document convention
  - Refactor inconsistent macros

- [ ] **Create coding standards document**
  - Document naming conventions
  - Document formatting style
  - Document comment style
  - Document error handling patterns
  - Add to `docs/coding-standards.md`

### Memory Management

- [ ] **Add allocation tracking in DEBUG mode**
  - Implement `mmt_alloc_debug()` with file/line tracking
  - Store allocation info in global table
  - Report leaks on shutdown

- [ ] **Implement GCC cleanup attribute wrapper**
  - Create `mmt_auto_free` macro
  - Add examples for scope-based cleanup
  - Document usage patterns

- [ ] **Integrate Valgrind in test pipeline**
  - Add `make valgrind` target
  - Run Valgrind on test suite
  - Fix all reported leaks
  - Add to CI/CD

- [ ] **Review and fix legacy code memory issues**
  - Files in `src/_old/` if retained
  - Replace unchecked malloc/calloc
  - Fix potential leaks

### Performance - Cache Optimization

- [ ] **Cache-align critical structures**
  - Align worker context to 64 bytes
  - Prevent false sharing in multi-threaded data
  - Add `__attribute__((aligned(64)))` where needed

- [ ] **Add prefetching in PCAP mode**
  - Similar to DPDK mode prefetching
  - Use `__builtin_prefetch()` or `rte_prefetch*()`
  - Prefetch 3 packets ahead in loop

- [ ] **Optimize data structure layouts**
  - Review struct padding
  - Group frequently-accessed fields
  - Minimize cache line crossings

### Architecture & Documentation

- [ ] **Create architecture documentation**
  - Document module interactions
  - Create sequence diagrams for packet flow
  - Document threading model
  - Explain process model (monitor/processing/control)

- [ ] **Create module interface diagrams**
  - Visualize module dependencies
  - Document data flow between modules
  - Explain callback mechanisms

- [ ] **Document configuration options**
  - Comprehensive config file reference
  - Explain all options with examples
  - Document default values and ranges

- [ ] **Create developer guide**
  - How to add new protocols
  - How to add new output modules
  - How to add new report types
  - Debugging tips and techniques

- [ ] **Create performance tuning guide**
  - DPDK vs PCAP selection criteria
  - Thread count recommendations
  - Buffer size tuning
  - Output module selection

### Technical Debt Management

- [ ] **Create GitHub issues for all critical vulnerabilities**
  - V1-V8: One issue per vulnerability
  - Add CWE and CVSS information
  - Link to audit report sections

- [ ] **Create GitHub issues for performance bottlenecks**
  - P1-P9: One issue per bottleneck
  - Add expected performance improvement
  - Link to audit report sections

- [ ] **Create GitHub issues for large function refactoring**
  - One issue per function over 100 lines
  - Document current complexity
  - Propose refactoring approach

- [ ] **Set up project milestones**
  - Milestone 1.6.1 (Week 2): Critical security fixes
  - Milestone 1.7.0 (Month 2): Performance optimizations
  - Milestone 2.0.0 (Month 4): Maintainability refactoring

- [ ] **Create project board for tracking**
  - Columns: Backlog, In Progress, Review, Done
  - Link all issues to board
  - Regular triage and prioritization

---

## 📈 Metrics & Tracking

### Code Quality Metrics (Target Goals)

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Cyclomatic Complexity | 5 functions >20 | All functions <15 | ⬜ Not Started |
| Function Length | 5 functions >100 lines | All functions <80 lines | ⬜ Not Started |
| Nesting Depth | Multiple >5 levels | All code <4 levels | ⬜ Not Started |
| Comment Density | 3-8% | 15-25% | ⬜ Not Started |
| Code Duplication | ~30-40% | <5% | ⬜ Not Started |
| API Documentation | Minimal | Complete (100%) | ⬜ Not Started |
| Magic Numbers | ~15% | <5% | ⬜ Not Started |
| Test Coverage | 0% | 70% | ⬜ Not Started |

### Security Metrics

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Critical Vulnerabilities | 4 | 0 | ⬜ Not Started |
| High Vulnerabilities | 11 | 0 | ⬜ Not Started |
| Medium Vulnerabilities | 12 | 0 | ⬜ Not Started |
| Static Analysis Issues | Unknown | 0 | ⬜ Not Started |
| Sanitizer Violations | Unknown | 0 | ⬜ Not Started |

### Performance Metrics

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Hash Table Worst-Case | O(n) | O(log n) | ⬜ Not Started |
| LPI Memory Usage | 512 MB | 1-10 MB | ⬜ Not Started |
| PCAP Latency Overhead | 100μs sleep | <10μs | ⬜ Not Started |
| Ring Buffer Throughput | Baseline | +30-50% | ⬜ Not Started |
| Overall Packet Rate | Baseline | +20-30% | ⬜ Not Started |

---

## 🎯 Quick Start Checklist (First Sprint)

Focus on these 8 critical items for maximum security impact:

- [ ] 1. Fix buffer overflow in socket_output.c (30 minutes)
- [ ] 2. Fix integer overflow in license.c MAC count (1 hour)
- [ ] 3. Fix integer overflow in license.c date calculation (1 hour)
- [ ] 4. Fix input validation in configure.c atoi calls (2 hours)
- [ ] 5. Optimize hash table load factor to 75% (2 hours)
- [ ] 6. Replace LPI bit array with sparse structure (4 hours)
- [ ] 7. Remove nanosleep from PCAP capture (4 hours)
- [ ] 8. Add static analysis to build system (2 hours)

**Estimated Time:** 16.5 hours (2 days)
**Impact:** Eliminates 4 critical vulnerabilities, improves performance by 50-70%

---

## 📝 Notes

### Legend
- ⬜ Not Started
- 🔄 In Progress
- ✅ Completed
- ⏸️ Blocked
- ❌ Cancelled

### Update Instructions

When working on an item:
1. Change `- [ ]` to `- [x]` when completed
2. Update the progress summary percentages
3. Update metrics tables with actual measurements
4. Add notes or links to related PRs/commits

### References
- **Audit Report:** `CPP_AUDIT_REPORT.md`
- **Security Details:** `SECURITY_VULNERABILITY_ASSESSMENT.md`
- **Remediation Plan:** `REMEDIATION_PLAN.md`
- **Issue Tracker:** GitHub Issues (to be created)
