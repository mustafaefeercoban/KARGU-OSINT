# Vendored resource dataset

`arf.json` — the OSINT Framework resource tree.

* Upstream: https://github.com/lockfale/OSINT-Framework
* Author: Justin Nordine · License: MIT (see upstream LICENSE)
* Vendored: 2026-09-01 (upstream commit "THE-169-opsec-enrichment")

Only the data file is used. None of the upstream JavaScript or Python is executed here.
Each entry carries `opsec: passive|active` plus an `opsecNote`, which is what the report
uses to tell you, before you click, whether a resource touches the target's own platforms.

Refresh with:
    curl -s https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json \
      -o ~/osint/resources/arf.json
