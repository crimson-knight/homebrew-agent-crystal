# Public SDK compiler readiness

The formula workflow keeps its ordinary source build, command aliases, formula
tests, and installer-script round trip. The added step uses that same installation
to exercise the exact public Memory Budget source candidate on macOS and Linux.

`sdk_source_lock.json` binds SDK commit
`08c30535c60b9097a5da664dc7072e89ec02cad7`, its codeload archive, all 93 Git
blobs and modes, the accepted Alpha formula, its exact source archive and version,
and the complete source-derived standard-library digest. The 22 standard-library
directory aliases carry their own exact target roster.

The run-local compiler profile derives from a reviewed policy: the installed
formula matches that source and version, its receipt identifies a source build,
the compiler wrapper names the installed backend, the complete installed standard
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
and output bound. The installed SDK and its fixtures supply compiler/runtime proof;
the Python tests challenge archive handling, source damage, directory aliases,
formula provenance and result acceptance independently.

`passed: true` applies to this readiness scope. The result explicitly retains false
values for full native-provider, frozen-dependency and customer-device acceptance.
