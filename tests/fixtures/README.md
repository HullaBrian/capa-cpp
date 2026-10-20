# test fixtures from mandiant/capa

These are capa's own language-agnostic test fixtures, copied unchanged from
[mandiant/capa](https://github.com/mandiant/capa) at commit
`d4cf889f20834f0418af38e9d46066048a4a72c5` (capa 9.4.0, 2026-10-06), under capa's Apache 2.0
license (`LICENSE-capa.txt`). They exist so that ports can verify themselves against
the reference implementation; capa-cpp runs them with `capa-tests`.

- `matcher/` — data-driven rule-matcher tests (capa#2985, capa PR #2987): a rule fragment, a
  synthetic feature listing in the show-features DSL, and the exact matches capa reports.
  See `matcher/README.md` for the format. `capa-tests match-fixtures` runs every one, with
  capa's "paranoid" check that the indexed matcher agrees with the naive one at every scope.
- `features/` — backend feature fixtures (capa#2743, capa PR #2986): for a sample, a location
  and a feature, whether the backend extracts it. See `features/README.md`. They need the
  samples from [mandiant/capa-testfiles](https://github.com/mandiant/capa-testfiles);
  `capa-tests feature-fixtures` evaluates them against a backend's freeze file.

To update: copy `tests/fixtures/{matcher,features}` from a newer capa checkout, update the
commit above, and run `capa-tests`. A newly failing fixture is a capa behavior the port has
not picked up yet.
