Start with [the56 exact API queries](API_ROSTER.json) and [thefour concrete receiver probes](#four-probes). All56 questions,17 GC fields and four fixture sources keep their existing exact bytes. COUNTER_PHASE_MAP.json derives source method/line/hash anchors from the full canonical9c1 archive, including authoritative526f boehm.cr. Historical roster line hints remain preserved separately.

These are intended measurements, with actual lookup/probe results still pending. The API phase asks whether the measurement interfaces are available and whether the exact receivers type-check. It does not yet run a retained-state census.

| Intended lever | Where to sample or count | Specific source interface | What it can show |
|---|---|---|---|
| GC allocation pressure | Initialized program, after parse, declarations, main inference, cleanup | GC.stats / GC.prof_stats; canonical boehm.cr391/407 | Requested allocation deltas, heap/free/unmapped state and collection/reclamation counters by phase. |
| Type growth | After declarations and main inference | Crystal::Type#types?; types.cr372 | Existing named-type counts and deduplicated type identities. |
| Generic specialization | Main inference and cleanup | Crystal::GenericType#each_instantiated_type; types.cr1576 | Number and owner identity of existing concrete type instantiations. |
| Typed method growth | Main inference and cleanup | Crystal::DefInstanceContainer#add_def_instance / #lookup_def_instance; types.cr895/899 | Cache entry, insertion and lookup/hit/miss counts by receiver/signature family. |
| Retained method/AST provenance | At the same phase boundaries | Crystal::Def#owner/#original_owner/#body; Call#target_defs; ASTNode#location | Source/expanded-macro ownership for deduplicated reachable methods and AST nodes; coverage and byte ownership still need later proof. |

The phase anchors are Compiler#new_program, Compiler#parse, Program#top_level_semantic, Program#visit_main and the cleanup block in Program#semantic. Each of the17 GC fields has its own exact getter and snapshot source in the JSON map. LLVM/codegen is listed as a later boundary; the current --no-codegen route never measures its allocation.

The diagnostic def_instances getter can allocate its Hash, so the concrete fixture instead reads existing nullable @def_instances. The same caution applies to constructing metaclasses. A later tiny runtime fixture must verify that traversal leaves the graph unchanged, measure its own allocation, distinguish insertion events from retained distinct objects, and report excluded edges.

GC.total_bytes is cumulative requested allocation. heap_size-free_bytes is an approximation of occupied GC heap. Collector snapshots, reachable object counts, retained bytes, process RSS and complete-build peak are separate quantities. A method/cache counter can identify a likely lever; an unchanged original/candidate/restored workload is still needed to prove its causal memory effect.

### Four probes

- [gc_stats.cr.txt](inputs/gc_stats.cr.txt): Prove all five Stats and twelve ProfStats fields accept UInt64. Expected exit 0; ceiling 300 seconds.
- [initialized_graph.cr.txt](inputs/initialized_graph.cr.txt): Prove initialized Program/type/generic/cache-key receiver compatibility; nullable existing-state accessors avoid initializing the observed caches. Expected exit 0; ceiling 300 seconds.
- [source_origins.cr.txt](inputs/source_origins.cr.txt): Prove method owners, bodies, call targets and source/macro-location receiver compatibility. Expected exit 0; ceiling 300 seconds.
- [gc_stats_wrong_type.cr.txt](inputs/gc_stats_wrong_type.cr.txt): Prove an actual UInt64/String incompatibility is refused, so a successful command cannot silently omit the tested code. Expected exit 1; ceiling 60 seconds.

All four also receive an exact15-second formatter check. The full phase retains123 possible commands and2280 command-seconds, with120 preparation and180 return seconds inside2700. Each raw card/unknown/verification, compiler diagnostic, proxy invocation and original-group return is retained.
