# Changelog

## [1.1.1] - 2026-09-15

- Report success against the requested phases while preserving selected runs for later continuation. Keep failed or budget-truncated requested phases pending in both implementations.
- Persist optional HTTP-source errors, missing discovery-tool warnings and Amass budget exhaustion. Download archive index responses before parsing so curl failures cannot be hidden by a successful downstream pipeline; retry transport failures within the existing budgets.
- Build release binaries with the current Go compiler to avoid older macOS linker incompatibilities, and keep the manifest version aligned with the release.

## [1.1.0] - 2026-09-15

- Use Amass database export (`enum` followed by `subs -names`) with the configured default engine/database instead of the removed `enum -o` flag. Preserve enumeration output and export diagnostics; engine or export failures produce explicit optional-source warnings.
- Separate optional-source degradation from required command and artifact failures. Successful enumeration can receive its checkpoint when another source fails or is unavailable; required DNS verification failures and cancellation remain pending.
- Preserve passive and crawl candidate inputs and unresolved names as durable artifacts. Retry bulk resolver misses independently with A/AAAA lookups, bounded concurrency, three retries and a maximum recovery rate of 500 queries per second. Disable bulk sanitization for already validated collected names so service-record labels are not silently discarded.
- Scale the default Katana budget from 45 minutes to six hours with seed count, checkpoint completed batches of at most 100 seeds, and retain partial output across interruption. Add `--crawl-budget` and `--resume-crawl` to extend unfinished crawling without replaying completed batches or archive sources. Budget-truncated crawl work is reported as pending.
- Add opt-in `--exclude-file` collection filters for exact hostnames and wildcard suffixes. Apply the same filters to passive input, TLS names, archived/crawled URLs, DNS recovery, seeds and master rebuilding; preserve suffix apex names and bind normalized filters to resumable runs.
- Keep Go and Bash hardening behavior aligned, ship the new shell helpers through the installer, report candidate and warning counts, and add offline regression fixtures for unsupported Amass flags, optional failures, DNS recovery, archive reintroduction and crawl continuation. Add an optional real-tool DNS compatibility check against a synthetic loopback server.

## [1.0.0] - 2026-09-14

- Publish the nine-phase Bash and Go LeetEnum pipeline.
- Add parallel passive sources, tiered and recursive brute force, gotator permutations, resolver health checks, auto-tuned profiles, JSONL output, and resumable reports.
- Remove the dedicated takeover phase and exclude takeover-tagged Nuclei templates.
- Isolate dry runs from saved scan state and preserve completed baselines for selected-phase reruns.
- Add CI, platform builds, installer checks, documentation, and release checksums.

Historical runs and old repository clones may contain earlier source versions.
