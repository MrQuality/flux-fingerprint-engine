# Contributing to FluxFingerprint

We welcome contributions from senior network engineers, systems architects, and security researchers who share our "physics-first" approach to network observability.

## 1. Legal Requirements (The Governance Protocol)

To maintain a sustainable project, FluxFingerprint operates under a **Dual-License Model**:
- **Open Source:** Contributions are distributed under the **GNU Affero General Public License version 3 (AGPLv3)**.
- **Commercial:** Contributions may also be included in proprietary, non-AGPL versions of the engine at the maintainers' discretion.

### Developer Certificate of Origin (DCO)
All commits must be signed-off (`-s`) to certify that you have the right to submit the code. This is a legally binding assertion defined in `DCO.md`.
```bash
git commit -s -m "feat(parser): add TLS 1.3 record layer validation"
```

### Contributor License Agreement (CLA)
By submitting a Pull Request, you agree to the terms in `CLA.md`. This agreement grants the project maintainers a license to use and re-license your contributions as part of both the OSS and Commercial versions of the engine.

## 2. Technical Standards

### Forensic Reporting
All bugs and feature proposals must use the provided forensic templates:
- **Bug Reports:** Provide deep failure mechanism analysis.
- **Pull Requests:** Document architectural pivots and performance compliance.

### Code Rigor
- **Zero-Copy Hot Path:** No hidden memory copies in packet processing.
- **Lockless Concurrency:** Shared-nothing parallelism with no hot-path mutexes.
- **Fail-Closed Parsing:** Protocol parsers must terminate on any bound violation or ambiguity.
- **Human Provenance:** All contributions must be of human origin. References to automated tools or synthetic authorship are strictly prohibited.

### Git LFS Requirement
This project uses **Git LFS** for binary PCAP fixtures.
```bash
git lfs install
```
