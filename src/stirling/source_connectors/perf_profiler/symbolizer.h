/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <memory>
#include <string>

#include "src/stirling/bpf_tools/bcc_bpf_intf/upid.h"
#include "src/stirling/bpf_tools/bcc_wrapper.h"

DECLARE_bool(stirling_profiler_symcache);

namespace px {
namespace stirling {

namespace profiler {
static constexpr uint32_t kKernelPIDAsU32 = ~0;
static constexpr upid_t kKernelUPID = {.pid = kKernelPIDAsU32, .start_time_ticks = 0};
}  // namespace profiler

/**
 * Symbol wraps a std::string for the sole and express purpose of
 * enabling <some map>::try_emplace() to *not* call into bcc_symbolizer->get_addr_symbol()
 * if the key already exists in that map. If we provide the symbol directly to try_emplace,
 * then get_addr_symbol() is called (costing extra work).
 */
class Symbol {
 public:
  Symbol(ebpf::BPFStackTable* bcc_symbolizer, const uintptr_t addr, const int pid)
      : symbol_(SymbolOrAddrIfUnknown(bcc_symbolizer, addr, pid)) {}

  inline const std::string& symbol() const { return symbol_; }

 private:
  static std::string SymbolOrAddrIfUnknown(ebpf::BPFStackTable* bcc_symbolizer,
                                           const uintptr_t addr, const int pid) {
    static constexpr std::string_view kUnknown = "[UNKNOWN]";
    std::string sym_or_addr = bcc_symbolizer->get_addr_symbol(addr, pid);
    if (sym_or_addr == kUnknown) {
      sym_or_addr = absl::StrFormat("0x%016llx", addr);
    }
    return sym_or_addr;
  }

  const std::string symbol_;
};

/**
 * Symbolizer: provides an API to resolve a program address to a symbol.
 * If FLAGS_stirling_profiler_symcache==true, it attempts to find the symbol
 * in its own symbol cache (i.e. because we believe the BCC side symbol
 * cache is less efficient).
 *
 * Symbolizer creates a 'bpf stack table' solely to gain access to the BCC
 * symbolization API (the underlying BPF shared map and BPF program are not used).
 *
 * A typical use case looks like this:
 *   auto symbolize_fn = symbolizer.GetSymbolizerFn(upid);
 *   const std::string symbol = symbolize_fn(addr);
 *
 */
class Symbolizer : public bpf_tools::BCCWrapper, public NotCopyMoveable {
 public:
  Status Init();
  void FlushCache(const struct upid_t& upid);

  std::function<const std::string&(const uintptr_t addr)> GetSymbolizerFn(
      const struct upid_t& upid);

  int64_t stat_accesses() { return stat_accesses_; }
  int64_t stat_hits() { return stat_hits_; }

 private:
  const std::string& Symbolize(absl::flat_hash_map<uintptr_t, Symbol>* symbol_cache, const int pid,
                               const uintptr_t addr);

  // We will use this exclusively to gain access to the BCC symbolization API;
  // i.e. while this does create a shared BPF "stack trace" map, we do not use that.
  std::unique_ptr<ebpf::BPFStackTable> bcc_symbolizer_;

  absl::flat_hash_map<struct upid_t, std::unique_ptr<absl::flat_hash_map<uintptr_t, Symbol> > >
      symbol_caches_;

  int64_t stat_accesses_ = 0;
  int64_t stat_hits_ = 0;
};

}  // namespace stirling
}  // namespace px