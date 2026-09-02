# Appendix B — API → CLI → dashboard parity matrix

The full matrix lives in [`parity-matrix.md`](parity-matrix.md) (F6.B builder
artifact; the fix-plan referenced this file under the Appendix B name — both
names resolve to the same matrix, with `parity-matrix.md` canonical).

Summary (2026-09-02, F6.B / R9-6):

- 42 Appendix B rows enumerated; **26 new CLI commands/subcommands built**;
  13 pre-existing; **0 missing** for in-MVP scope.
- New API endpoints: `POST /api/packs/enable`, `/api/packs/disable`,
  `/api/packs/update`, `POST /api/reload`, `POST /api/scan`, `GET /ui`
  (redirect), plus `tool`/`since` filters on `GET /api/events|stats` and
  `effective_rules` in the policy document.
- Dashboard: per-pack enable/disable + update buttons (§4.6-named) and the
  "Test detection" box (B.4-named) added; rows whose UI leg is outside the
  §4.6 config-screens list are explicitly marked (see notes N1–N3).
- CI-runnable parity test: `crates/cerberus/src/main.rs::cli_tests::
  every_daemon_backed_cli_command_maps_to_a_real_api_route` walks the matrix
  and asserts every daemon-backed CLI command's endpoint exists in
  `cerberus_proxy::api::known_api_routes()`.
