# Full BPF_STREAM_PARSER-off Image experiment — 15 November 2026

**Experimental branch:** research/kmi-full-parser-off-20261115.
**Base commit:** 30843a779ee3e6a2ffe6d00b9d9154888222476b (Draft PR #3).
**Status:** CI experiment prepared; no completed full parser-off build recorded yet.

The workflow makes **two independently linked full kernels on the same runner**:
1. Original parser-on Image, vmlinux, vmlinux.symvers, .config in kout.
2. Parser-off Image, vmlinux, vmlinux.symvers, .config in
   kmi-full-parser-off-output from an isolated copy of the same patched source.

The second build starts from the actual first build .config, disables
CONFIG_BPF_STREAM_PARSER, runs olddefconfig, and checks that the only
effective deltas are BPF_STREAM_PARSER=y -> n plus the verified
STREAM_PARSER=y -> n/absent Kconfig select consequence.
Any other delta aborts the second build. IP_SET, IPv6 NAT, the rest of BPF,
Droidspaces, and all other configuration inputs are preserved.

The variant uses the same AOSP Clang, cross settings, thin-LTO wrapper,
KCFLAGS, AFDO_CFLAGS, and EXTRA_CFLAGS as the first build.
The source ZIP SHA256 (mutable upstream branch), patch repo commits when
available, source snapshot checksums, Clang/LLD versions, input
profile checksum, and resulting Image/vmlinux/symvers checksums are captured.
Same-run comparison isolates the parser effect despite upstream branch drift.

The kmi-full-parser-off-<run-id> Actions artifact contains the full experimental
Image (not a GitHub Release), resolved configs, both full vmlinux.symvers,
a complete per-export and STG comparison, provenance JSON, and build logs.
No flashing, reboot, insmod, SELinux changes, or MODVERSIONS bypass takes place.
The normal master defaults and original KMI research branch are unchanged.

The public CI has no private original 593-module manifest: the report must
explicitly say UNVERIFIED for real module-import compatibility. Even if
19 CRCs return to STG, do not claim full module compatibility or boot safety.
Do not adopt a production parser-off policy before measuring the complete
Image and discussing the SOCKMAP/SOCKHASH parser functionality.
