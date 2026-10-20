# Public SDK compiler readiness

The formula workflow keeps its ordinary source build, command aliases, formula
tests, and installer-script round trip. The added step uses that same installation
to exercise the exact public Memory Budget source candidate on macOS and Linux.

`sdk_source_lock.json` binds SDK commit
`08c30535c60b9097a5da664dc7072e89ec02cad7`, its codeload archive, all 93 Git
blobs and modes, the accepted Alpha formula, its exact source archive and version,
and the complete source-derived standard-library digest. The 22 standard-library
directory aliases carry their own exact target roster.

Formula revision 1 excludes the generated `llvm/ext/llvm_ext.o` compiler-build
object, matching the pinned upstream install target. Source version and installed
package revision are checked separately. The source-derived standard-library
digest remains exact, and the actual file roster is saved before comparison so a
failed check retains the difference for review.

The run-local compiler profile derives from a reviewed policy: the installed
formula matches that source and version, its receipt identifies a source build,
the compiler wrapper matches the literal Homebrew Bash template, including its
interpreter, environment assignments, quoted backend and argument forwarding, the complete installed standard
library matches the separately pinned release source, and the actual compiler and
Ruby executable hashes remain fixed throughout execution. This schema-1 profile
qualifies compiler/spec/tutorial readiness. Native and Git provider admission,
schema-3 frozen dependency installation, full build memory, independent customer
devices, and a supported SDK release retain separate acceptance checks.

The actual behavior gate requires:

1. An ordinary hash-verified 67-member bundle installation, including the docs and
   skill, in a consumer path containing spaces; the manifest is the 68th file.
2. Exactly 39 passing examples with the default runtime and 39 with `-Dwithout_mt`,
   each through the installed SDK runner and one compiler code-generation thread.
3. One build of the installed documentation tutorial. That same identified binary
   passes normally and exits 1 when its real extra-allocation regression is enabled.
   Both controls execute the tutorial's functional record assertions.
4. GREEN compiler output, exact source/provider identities after execution, and
   removal of the private source, prepared standard libraries, binaries and caches.

The step reserves 15 minutes within the 75-minute formula job, admits a 3-GiB disk
projection above a 10-GiB free-space floor, and retains raw command output and a
machine-readable result even when a check fails. Each command has a finite timeout
and output bound. After its direct child returns, the runner observes the original
POSIX process group for up to five seconds, capped by the original command and
complete-step deadlines. Initial and terminal samples record the observed retirement
interval. Confirmed absence admits its output hashes. A present or
unverifiable group refuses the command and preserves its private source and cache.
Cleanup failures retain both the original error and the cleanup error in the
result. Unresolved Linux groups also retain bounded process identity/state metadata
with names and arguments omitted. This group observation covers the original group; process recovery and
detached sessions retain separate qualification gates.

Before the installation, a separate hosted control exercises a real normal exit,
a same-group child that naturally retires after 0.6 seconds, and a held same-group
descendant that remains after its leader exits. Natural retirement must be observed
inside the original command interval before its output is accepted. The held child must
earn a refused command with null output hashes. Its cooperative self-exit and a
subsequent group-absence observation produce separate receipts before private-cache
removal. The control pins its script and the complete reviewed driver, records the
observed Python version and executable hash before and after execution, and retains
its own artifact. It admits at most two concurrent fixture processes, 45 seconds,
and 1 MiB of evidence. Group recovery and detached sessions remain separate gates.

The installed SDK and its fixtures supply compiler/runtime proof;
the Python tests challenge archive handling, source damage, directory aliases,
formula provenance and result acceptance independently.

`passed: true` applies to this readiness scope. The result explicitly retains false
values for full native-provider, frozen-dependency and customer-device acceptance.

## Linux native projection candidate

After the ordinary formula source install succeeds, Ubuntu records a separate bounded
native projection candidate even when later arithmetic smoke, installer round-trip,
or SDK steps refuse. Those ordinary behavior gates retain their required results.
A missing or altered final installation prefix earns the collector's own retained
refusal. The collector reuses the exact
reviewed command runner and stable identity reader. It checks the formula, full
compiler version and complete installed standard library, then records toolchain,
loader, GMP/SQLite, package origins, header candidates and lexical/physical aliases.
The candidate identifies paths outside the proposed read-only mounts, including
`/etc/alternatives`, and preserves unresolved ELF/header/link choices for review.

Collection admits 150 seconds, 32 metadata commands, 8,192 entries, 2 GiB of
unique hash inputs, 256 MiB per file and 32 MiB of raw command output. Every command
retains its argv, complete raw streams and original-group observation. A separate
artifact is retained on success or refusal. The candidate grants zero native-profile
or build admission; independent exact-roster review and actual loader/link/GMP/SQLite
controls are required before a representative Grant build.

## Linux generated-code CPU diagnostic

The observed Ubuntu source installation completes, and the arithmetic smoke command
reports an invalid instruction while executing its generated program. A separate
240-second diagnostic runs after successful formula installation, including when
that ordinary smoke step fails. It compares default targeting with an explicit
`--mcpu generic` using the same installed compiler, standard library, wrappers,
arithmetic source, and isolated caches. Each build, generated-program execution,
and eval retains its actual status. CPU advertisements, disassembly, and an
available debugger's fault location support attribution to a particular instruction
and feature. Protected source/provider identities are rechecked afterward.

The diagnostic pins its source and reviewed command runner, preserves the ordinary
smoke result, and writes its own artifact. It admits 32 MiB of aggregate raw output
and generated binaries up to 16 MiB each. The final elapsed-time observation includes
provider verification; finalization failures retain the original command and cleanup
errors. Diagnostic completion supplies evidence for a compiler repair. Ordinary
smoke, SDK readiness, and supported-installation acceptance each retain their own
required behavior gates.

### Preserved Homebrew context and distro SQLite successor

At exact source `1320d494717f7cd70ea83ff2f1c88f4f6f73a138`, Ubuntu run
`39483326475` passes the ordinary default arithmetic smoke. Its diagnostic then
refuses a Homebrew receipt query as an untrusted-tap request before compiling
either diagnostic target. The native collector separately reaches Homebrew GMP
metadata and refuses its Homebrew pkgconf SQLite query, even though the retained
Ubuntu package receipt records SQLite and its development package as installed.
Those original failures remain exact; an offending instruction remains unobserved.

The successor retains an explicit safe Homebrew metadata environment with the
ordinary USER/LOGNAME, XDG configuration, Homebrew identity/update settings, and
non-secret CI identity. Tap trust enforcement stays active. Both metadata controls
use the same lexical Homebrew entrypoint and argv, fixed no-auto-update/no-analytics
settings, and separate preserved versus compiler-filtered user/config context.
An observed filtered-environment refusal keeps its actual status and retired raw
hashes. Default and generic compilation continue through the same filtered
environment with explicit target flags and isolated caches; `CRYSTAL_OPTS` stays
outside both contrasts. Formula, wrapper, source, provider, standard-library, group,
and final elapsed-time checks remain required.

Native metadata retains the original Homebrew SQLite query as an explicitly
observed control. It separately identifies `/usr/bin/pkg-config`, its lexical
aliases and physical provider, and its version/default search metadata. SQLite
queries use that distro provider with explicit `/usr/lib/x86_64-linux-gnu/pkgconfig`,
`/usr/lib/pkgconfig`, and `/usr/share/pkgconfig` roots and an empty additional path
and sysroot. The selected SQLite PC source must belong to those roots. Homebrew
GMP retains its own observed provider. Required metadata queries still require
zero exit, exact argv and provider identities, confirmed original-group absence,
and complete raw hashes. The additional controls stay inside the existing
32-command, 150-second, entry/hash-input/file/output limits.

The CPU diagnostic now runs after ordinary SDK execution, with the same
always-after-successful-source-install condition. Each ordinary behavior gate
retains its own result when a later diagnostic refuses. The original 84 source
cases and 14 added context/provider controls pass in ordinary and optimized local
Python with actual process creation guarded. Actual successor hosted behavior,
complete headers/link/loader choices, native-profile admission, SDK readiness on
each new installation, and the full Grant build remain separate pending gates.
