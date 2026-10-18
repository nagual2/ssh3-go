# FROZEN — do not build, do not audit, do not extend

The Rust workspace was declared **frozen (dormant)** by the repository owner
on 2026-10-13. As of that date:

- nothing here is built by CI or shipped in any release artifact — goreleaser
  builds the Go binaries only;
- no bug report or audit finding in this directory is scheduled for a fix:
  the pass-5/pass-6 Rust findings (F-16, F-20, and the pass-6 F-19 client
  residual) are frozen together with the code;
- audits: **skip this directory entirely**, do not spend budget on it.

The workspace stays in the tree as an inherited experimental lineage. If the
owner ever decides to productize it, unfreeze explicitly — update this file
and the README banner, then re-run a fresh audit pass over it first.
