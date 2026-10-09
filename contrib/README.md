# banlist.py

Validates the dataset in `entities/`, generates the banlist text files and the
static website. Requires Python 3.11 or newer and no third-party packages.

```
python contrib/banlist.py validate
python contrib/banlist.py banlist OUTDIR [--bantime-days N]
python contrib/banlist.py site OUTDIR [--bantime-days N]
```

- `validate` loads `tags.toml` and every `entities/*.toml` (plus `*.ips.txt`
  sidecars), reports all schema errors, and exits non-zero if there are any.
- `banlist` writes `banlist_cli.txt`, `banlist_gui.txt` and `banlist_plain.txt`
  for the active networks of active entities.
- `site` writes everything `banlist` writes plus `index.html`, one
  `<slug>/index.html` per entity, `entities.json`, `schema.json` and `style.css`.

`--bantime-days` sets the default ban duration for entities that do not set
`bantime_days` themselves. Templates live in `templates/` (Python
`string.Template` syntax), the stylesheet in `static/style.css`.
