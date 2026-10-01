# target-shop (lab target)

> **INTENTIONALLY VULNERABLE (v1).** Never deploy it, never expose it. It runs only on the isolated
> `lab` Docker network (`internal: true`: no internet, no host port).

A small e-commerce app (Spring Boot 3, Java 21, in-memory H2) that Sentinel defends and the attack lab
attacks. One codebase, two behaviours selected by `SHOP_VERSION`:

| | v1 (default) | v2 |
|---|---|---|
| Purpose | the vulnerable target | the same app with every finding fixed |
| Findings | F-01 to F-14 (see `docs/owasp-findings.md`) | none of them exploitable |

Run: `(cd target-shop && mvn -q package) && docker compose --profile core up -d target-shop`
(v2: `SHOP_VERSION=v2 docker compose --profile core up -d target-shop`).

Tests: `mvn -q test` runs 16 tests proving each v1 flaw is exploitable and 18 proving v2 closes it.

## Logs
Every request and every login attempt is published to Kafka (`logs.app`, `logs.auth`) as JSON from a
background thread with a bounded queue, so a slow broker can never slow down or fail a request.
`python -m sentinel.ingest.normalize` turns them into `events.normalized` for the detection engine.
Fields such as the URL and username are attacker-controlled and are treated as hostile input downstream.

## Seed accounts (lab only)
`admin/admin` (v1), `alice/sunshine`, `bob/letmein`, `carol/qwerty123`. v2 uses `SHOP_ADMIN_PASSWORD`
(or a random one) for the admin and BCrypt for everything.
