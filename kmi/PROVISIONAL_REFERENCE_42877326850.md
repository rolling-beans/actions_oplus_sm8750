# Provisional BTF type-layout reference (NOT boot verified)

- Source: GitHub Actions workflow_dispatch run 42877326850 (kernel build #233).
- Monitored structs: task_struct, cgroup, cfs_rq, rq, task_group.
- SHA-256 type-layouts.txt: `8396b94724d7cbd20abc7f7ab0dbb1387119fa345b0f4159967e2f188e59b778`.
- Generated via `pahole -F btf -C task_struct,cgroup,cfs_rq,rq,task_group`.
- **This build has not been confirmed booted on the user's OnePlus 13.**
- Provenance is public CI; reference must only be used to flag *changes*, never to assert device compatibility or permit flashing.
- Do not use this as an automatically approved STG reference. Obtain boot-verified reference from the actual device/kernel build before promoting.
