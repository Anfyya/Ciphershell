# Reference runtime fingerprint provenance

`kReferenceRuntimes` is a deny-list for byte-exact retired interpreter code.
Every row below is part of the security data, not an illustrative checksum.
The static gate parses the C++ initializers and this table together, recomputes
the rolling-window power, and rejects a missing, duplicate, or mismatched row.

The common historical boundary is:

- source tree: `bb01871c9ec0037270b3d1bcf9346a190ee252ff` (`update md`,
  2026-07-13 02:50:23 +0800);
- capture/retirement commit:
  `36c261f3c6cd6354df966c04438330032f8bfc40` (`5.6Sol做一半`,
  2026-07-13 17:37:19 +0800), the commit that removed the embedded runtime
  build path and introduced these four recorded values;
- input sources: `runtime/common/vm_runtime_core.c`, `vm_crypto.c`, and the
  architecture-specific `runtime/x64/native_bridge.asm` or
  `runtime/x86/native_bridge.asm` from the source tree above;
- compiler family: the active Visual Studio 2022 MSVC toolset and Windows SDK
  selected by that tree's CMake configuration, plus NASM. The exact MSVC/SDK
  patch versions were not persisted, so these entries are historical capture
  identities, not a promise that a later toolchain can reproduce the bytes.

The full-image build recipe is preserved in the parent commit's
`CMakeLists.txt`: C sources use
`/nologo /c /TC /O1 /GS- /GR- /Oi- /Zl /W3`; x64 links with
`/NODEFAULTLIB /SUBSYSTEM:CONSOLE /MACHINE:X64 /DYNAMICBASE /NXCOMPAT
/BASE:0x180000000 /ENTRY:vm_runtime_interpret`; x86 uses the corresponding
`/MACHINE:X86 /BASE:0x10000000 /SAFESEH:NO` command. Fingerprints cover
file-backed `.text` bytes, not PE headers.

## Fingerprint manifest

| Provenance ID | Architecture / capture | Size | Rolling hash | Leading power | SHA-256 |
|---|---|---:|---|---|---|
| `legacy-msvc-x64-full-bb01871` | x64 full `.text` from the parent-tree production runtime build | 23552 | `2c5fc69ee2383e78` | `e6224086755cff01` | `fa0c6f3e275f620bf51f19af5f1cd3a46ec10431176d53eb4296637acc5a26dc` |
| `legacy-msvc-x86-full-bb01871` | x86 full `.text` from the parent-tree production runtime build | 24064 | `a15835ec2011743a` | `a9a6c919725eff01` | `bb843d6555cf8dfc531ae404c7974c21d1bfeac36fc6362986565724a3d34398` |
| `legacy-msvc-x64-probe-bb01871` | x64 0x2e00-byte retirement probe captured from that generated runtime during the 36c261f migration | 11776 | `72544b6cbfec2e4f` | `c3455fa1ba2eff01` | `0bca0748cc32c713f415563cc82ed93d621c53e59ba9f67998af98da36dbfdd0` |
| `legacy-msvc-x86-probe-bb01871` | x86 0x2e00-byte retirement probe captured from that generated runtime during the 36c261f migration | 11776 | `b58e1dfe08ee6c7e` | `c3455fa1ba2eff01` | `2b25ce2779b50e4d4e4340f638773e5c76cdbdcb3c93d9f768fe4911b36af7ff` |

The two probe extraction byte ranges were recorded only as digests in the
retirement commit; its temporary extraction utility and raw generated PE files
were not committed. This limitation is stated explicitly so the probe rows are
not misrepresented as reproducible CI artifacts. They still identify the
specific parent-tree build/capture event above and remain in the deny-list as
additional defense; the two complete `.text` rows are the authoritative full
runtime fingerprints.

## Update rule

Adding a row requires all of the following in the same change: source commit,
capture commit or durable CI artifact identity, architecture and exact build
command, byte-range definition, size, rolling hash, leading power, SHA-256,
and a unique provenance ID. A constant without that record must fail the
static gate; changing only prose or a symbol name cannot satisfy it.
