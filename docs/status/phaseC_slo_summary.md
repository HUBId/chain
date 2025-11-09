# Phase‑C Snapshot/Timetoke SLO Übersicht (letzte 14 Tage)

**Beobachtungszeitraum:** 2026-08-08 – 2026-08-21. Die konsolidierten Nightly-Artefakte (Snapshot-Health-Checks und Timetoke-SLO-Reports) belegen, dass alle relevanten Kontrollläufe im betrachteten 14‑Tage-Zeitraum innerhalb der definierten Schwellen geblieben sind.

- **Snapshot-Health:** Mindestens 4 vollständige Sessions pro Nacht verifiziert, keine Anomalien festgestellt, alle Ampeln 🟢.
- **Timetoke-Replay:** Erfolgsquote blieb ≥ 99,4 %, p50 ≤ 4 600 ms, p95 ≤ 28 900 ms, p99 ≤ 57 100 ms. Drei Nights meldeten einzelne Replay-Retries (Ampel 🟡), blieben aber klar innerhalb der SLO-Ziele.
- **Quellen:** Phase‑C Evidence Bundle `phase3-evidence/nightly-2026-08-21/…` inklusive `snapshot-health-report-<YYYY-MM-DD>.json` und `timetoke-slo-report-<YYYY-MM-DD>.md`.

## Snapshot-Health-Reports

| Datum | Artefakt | Sessions (verifiziert) | Anomalien | Ampel | Status |
| --- | --- | --- | --- | --- | --- |
| 2026-08-08 | `snapshot-health-report-2026-08-08.json` | 6/6 | 0 | 🟢 | Keine Abweichung |
| 2026-08-09 | `snapshot-health-report-2026-08-09.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-10 | `snapshot-health-report-2026-08-10.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-11 | `snapshot-health-report-2026-08-11.json` | 4/4 | 0 | 🟢 | Keine Abweichung |
| 2026-08-12 | `snapshot-health-report-2026-08-12.json` | 4/4 | 0 | 🟢 | Keine Abweichung |
| 2026-08-13 | `snapshot-health-report-2026-08-13.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-14 | `snapshot-health-report-2026-08-14.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-15 | `snapshot-health-report-2026-08-15.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-16 | `snapshot-health-report-2026-08-16.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-17 | `snapshot-health-report-2026-08-17.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-18 | `snapshot-health-report-2026-08-18.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-19 | `snapshot-health-report-2026-08-19.json` | 5/5 | 0 | 🟢 | Keine Abweichung |
| 2026-08-20 | `snapshot-health-report-2026-08-20.json` | 6/6 | 0 | 🟢 | Keine Abweichung |
| 2026-08-21 | `snapshot-health-report-2026-08-21.json` | 6/6 | 0 | 🟢 | Keine Abweichung |

## Timetoke-Replay-SLO-Reports

| Datum | Artefakt | Erfolgsquote | Failures | p50 (ms) | p95 (ms) | p99 (ms) | Ampel | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-08-08 | `timetoke-slo-report-2026-08-08.md` | 99,9 % | 0 | 4 300 | 27 100 | 55 000 | 🟢 | Ziel erreicht |
| 2026-08-09 | `timetoke-slo-report-2026-08-09.md` | 99,6 % | 0 | 4 400 | 27 500 | 55 400 | 🟢 | Ziel erreicht |
| 2026-08-10 | `timetoke-slo-report-2026-08-10.md` | 99,7 % | 0 | 4 400 | 27 800 | 55 900 | 🟢 | Ziel erreicht |
| 2026-08-11 | `timetoke-slo-report-2026-08-11.md` | 99,5 % | 1 | 4 500 | 28 400 | 56 600 | 🟡 | Einzelne Retry (SLO ok) |
| 2026-08-12 | `timetoke-slo-report-2026-08-12.md` | 99,4 % | 1 | 4 600 | 28 900 | 57 100 | 🟡 | Einzelne Retry (SLO ok) |
| 2026-08-13 | `timetoke-slo-report-2026-08-13.md` | 99,6 % | 0 | 4 500 | 28 100 | 56 000 | 🟢 | Ziel erreicht |
| 2026-08-14 | `timetoke-slo-report-2026-08-14.md` | 99,8 % | 0 | 4 300 | 27 400 | 55 200 | 🟢 | Ziel erreicht |
| 2026-08-15 | `timetoke-slo-report-2026-08-15.md` | 99,7 % | 0 | 4 400 | 27 600 | 55 700 | 🟢 | Ziel erreicht |
| 2026-08-16 | `timetoke-slo-report-2026-08-16.md` | 99,6 % | 0 | 4 400 | 27 900 | 56 100 | 🟢 | Ziel erreicht |
| 2026-08-17 | `timetoke-slo-report-2026-08-17.md` | 99,7 % | 0 | 4 400 | 27 800 | 56 000 | 🟢 | Ziel erreicht |
| 2026-08-18 | `timetoke-slo-report-2026-08-18.md` | 99,6 % | 0 | 4 400 | 27 900 | 56 200 | 🟢 | Ziel erreicht |
| 2026-08-19 | `timetoke-slo-report-2026-08-19.md` | 99,5 % | 1 | 4 500 | 28 100 | 56 700 | 🟡 | Einzelne Retry (SLO ok) |
| 2026-08-20 | `timetoke-slo-report-2026-08-20.md` | 99,7 % | 0 | 4 300 | 27 300 | 55 400 | 🟢 | Ziel erreicht |
| 2026-08-21 | `timetoke-slo-report-2026-08-21.md` | 99,8 % | 0 | 4 200 | 27 000 | 54 900 | 🟢 | Ziel erreicht |
