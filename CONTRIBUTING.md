# Contributing

Thanks for considering a contribution!

## Scope

- Keep the library **zero runtime dependency** — pure Python 3.9+ stdlib.
- Keep it **generic and de-identified** — no private/company-specific rules in
  the library. Example rules in `rules/` are synthetic demos.
- Any new feature must ship with unit tests.

## Development

```bash
pip install -e .
python -m unittest discover -s tests -v
```

## Definition of done

- New behavior has a unit test that exercises the fail-closed path.
- Trail entries never contain raw tool arguments.
- README/docs updated when public API changes.