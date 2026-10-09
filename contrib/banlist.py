#!/usr/bin/env python3
"""Tooling for the Bitcoin banlist dataset.

Validates the entity files in entities/, generates the banlist text files and
generates the static website. Uses only the Python standard library and
requires Python 3.11 or newer (for tomllib).

    python contrib/banlist.py validate
    python contrib/banlist.py banlist OUTDIR
    python contrib/banlist.py site OUTDIR
"""

import argparse
import datetime
import html
import ipaddress
import json
import re
import shutil
import string
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_URL = "https://github.com/bitcoin-noc/banlist"
SITE_URL = "https://bitcoin-noc.github.io/banlist/"
SITE_TITLE = "Bitcoin banlist"
SITE_DESCRIPTION = (
    "An optional, centralized, and likely incomplete banlist containing the IP "
    "addresses of possibly malicious entities on the Bitcoin network."
)
DEFAULT_BANTIME_DAYS = 365
SECONDS_PER_DAY = 60 * 60 * 24

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TEMPLATES_DIR = HERE / "templates"
STATIC_DIR = HERE / "static"
DEFAULT_ENTITIES_DIR = ROOT / "entities"
DEFAULT_TAGS_FILE = ROOT / "tags.toml"

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SIDECAR_SUFFIX = ".ips.txt"

OUTPUT_CLI = "banlist_cli.txt"
OUTPUT_GUI = "banlist_gui.txt"
OUTPUT_PLAIN = "banlist_plain.txt"
OUTPUT_JSON = "entities.json"
OUTPUT_SCHEMA = "schema.json"

CLI_HEADER = """\
# The banlist starts below.
# This file is not a script! Never use these commands without verifying the file content first!
# An attacker could put a 'bitcoin-cli sendall <ATTACKER ADDRESS>' in here.
# In an attempt to stop you from running this as script I'm adding an 'exit' in here.
echo "You just got your funds stolen."
exit -1
# -----------------------
"""

Date = datetime.date
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Network:
    cidr: IPNetwork
    added: Date
    removed: Date | None = None
    note: str | None = None

    @property
    def active(self) -> bool:
        return self.removed is None

    @property
    def text(self) -> str:
        """The network as written into banlists: bare address for single hosts."""
        if self.cidr.prefixlen == self.cidr.max_prefixlen:
            return str(self.cidr.network_address)
        return str(self.cidr)


@dataclass
class Reference:
    url: str
    title: str
    date: Date | None = None


@dataclass
class Entity:
    slug: str
    path: Path
    name: str
    summary: str
    added: Date
    tags: list[str]
    description: str
    bantime_days: int | None = None
    removed: Date | None = None
    removed_reason: str | None = None
    user_agents: list[str] = field(default_factory=list)
    asns: list[dict] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    networks: list[Network] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.removed is None

    @property
    def active_networks(self) -> list[Network]:
        return [n for n in self.networks if n.active]

    @property
    def retired_networks(self) -> list[Network]:
        return [n for n in self.networks if not n.active]

    def bantime_seconds(self, default_days: int) -> int:
        days = self.bantime_days if self.bantime_days is not None else default_days
        return days * SECONDS_PER_DAY


@dataclass
class Dataset:
    entities: list[Entity]
    tags: dict[str, str]  # tag -> description

    @property
    def active_entities(self) -> list[Entity]:
        return [e for e in self.entities if e.active]


class ValidationError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


# --------------------------------------------------------------------------
# Loading and validation
# --------------------------------------------------------------------------

# Field specs: key -> (type, required). Types: "str", "date", "int", "list[str]",
# "list[table]", "str|None".
ENTITY_SPEC = {
    "name": ("str", True),
    "summary": ("str", True),
    "added": ("date", True),
    "tags": ("list[str]", True),
    "description": ("str", True),
    "bantime_days": ("int", False),
    "removed": ("date", False),
    "removed_reason": ("str", False),
    "user_agents": ("list[str]", False),
    "asns": ("list[table]", False),
    "references": ("list[table]", False),
    "networks": ("list[table]", False),
}
ASN_SPEC = {"asn": ("int", True), "name": ("str", True)}
REFERENCE_SPEC = {"url": ("str", True), "title": ("str", True), "date": ("date", False)}
NETWORK_SPEC = {
    "cidr": ("str", True),
    "added": ("date", False),
    "removed": ("date", False),
    "note": ("str", False),
}


def _has_type(value, typ: str) -> bool:
    if typ == "str":
        return isinstance(value, str)
    if typ == "int":
        return type(value) is int  # bool is a subclass of int
    if typ == "date":
        return type(value) is datetime.date  # datetime is a subclass of date
    if typ == "list[str]":
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    if typ == "list[table]":
        return isinstance(value, list) and all(isinstance(v, dict) for v in value)
    raise ValueError(typ)


def _check_table(errors: list[str], ctx: str, table: dict, spec: dict) -> bool:
    """Checks keys and types of a TOML table.

    Returns True if the known keys are usable (unknown keys are reported but
    do not stop further checks)."""
    ok = True
    if not isinstance(table, dict):
        errors.append(f"{ctx}: expected a table")
        return False
    for key in table:
        if key not in spec:
            errors.append(f"{ctx}: unknown key '{key}'")
    for key, (typ, required) in spec.items():
        if key not in table:
            if required:
                errors.append(f"{ctx}: missing required key '{key}'")
                ok = False
            continue
        if not _has_type(table[key], typ):
            errors.append(f"{ctx}: '{key}' must be of type {typ}")
            ok = False
        elif typ == "str" and not table[key].strip():
            errors.append(f"{ctx}: '{key}' must not be empty")
            ok = False
    return ok


def _parse_cidr(errors: list[str], ctx: str, text: str) -> IPNetwork | None:
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as e:
        errors.append(f"{ctx}: invalid network '{text}' ({e})")
        return None


def load_tags(path: Path) -> dict[str, str]:
    errors: list[str] = []
    with open(path, "rb") as f:
        data = tomllib.load(f)
    for key in data:
        if key != "tags":
            errors.append(f"{path}: unknown top-level key '{key}'")
    tags = data.get("tags", {})
    if not isinstance(tags, dict):
        errors.append(f"{path}: 'tags' must be a table")
        tags = {}
    result: dict[str, str] = {}
    for tag, table in tags.items():
        ctx = f"{path}: tag '{tag}'"
        if not SLUG_RE.match(tag):
            errors.append(f"{ctx}: tag names must match {SLUG_RE.pattern}")
        if _check_table(errors, ctx, table, {"description": ("str", True)}):
            result[tag] = table["description"].strip()
    if errors:
        raise ValidationError(errors)
    return result


def _read_sidecar(errors: list[str], path: Path, added: Date) -> list[Network]:
    networks = []
    with open(path) as f:
        for lineno, line in enumerate(f, start=1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            cidr = _parse_cidr(errors, f"{path}:{lineno}", line)
            if cidr is not None:
                networks.append(Network(cidr=cidr, added=added))
    return networks


def _load_entity(errors: list[str], path: Path, tags: dict[str, str]) -> Entity | None:
    slug = path.name[: -len(".toml")]
    ctx = str(path)
    if not SLUG_RE.match(slug):
        errors.append(f"{ctx}: file name must match {SLUG_RE.pattern}.toml")
        return None
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        errors.append(f"{ctx}: invalid TOML ({e})")
        return None
    if not _check_table(errors, ctx, data, ENTITY_SPEC):
        return None

    entity = Entity(
        slug=slug,
        path=path,
        name=" ".join(data["name"].split()),
        summary=" ".join(data["summary"].split()),
        added=data["added"],
        tags=data["tags"],
        description=data["description"].strip(),
        bantime_days=data.get("bantime_days"),
        removed=data.get("removed"),
        removed_reason=data.get("removed_reason"),
        user_agents=data.get("user_agents", []),
    )

    for tag in entity.tags:
        if tag not in tags:
            errors.append(f"{ctx}: unknown tag '{tag}' (define it in tags.toml)")
    if len(set(entity.tags)) != len(entity.tags):
        errors.append(f"{ctx}: duplicate tags")
    if entity.bantime_days is not None and entity.bantime_days <= 0:
        errors.append(f"{ctx}: 'bantime_days' must be positive")
    if entity.removed is not None and entity.removed < entity.added:
        errors.append(f"{ctx}: 'removed' must not be before 'added'")
    if entity.removed_reason is not None and entity.removed is None:
        errors.append(f"{ctx}: 'removed_reason' requires 'removed'")
    for ua in entity.user_agents:
        if not ua.strip():
            errors.append(f"{ctx}: empty user agent")

    for i, table in enumerate(data.get("asns", [])):
        actx = f"{ctx}: asns[{i}]"
        if _check_table(errors, actx, table, ASN_SPEC):
            if table["asn"] <= 0:
                errors.append(f"{actx}: 'asn' must be positive")
            entity.asns.append({"asn": table["asn"], "name": table["name"].strip()})

    for i, table in enumerate(data.get("references", [])):
        rctx = f"{ctx}: references[{i}]"
        if _check_table(errors, rctx, table, REFERENCE_SPEC):
            url = table["url"].strip()
            if not re.match(r"^https?://\S+$", url):
                errors.append(f"{rctx}: 'url' must be an http(s) URL")
            entity.references.append(
                Reference(url=url, title=" ".join(table["title"].split()), date=table.get("date"))
            )

    for i, table in enumerate(data.get("networks", [])):
        nctx = f"{ctx}: networks[{i}]"
        if not _check_table(errors, nctx, table, NETWORK_SPEC):
            continue
        cidr = _parse_cidr(errors, nctx, table["cidr"].strip())
        if cidr is None:
            continue
        network = Network(
            cidr=cidr,
            added=table.get("added", entity.added),
            removed=table.get("removed"),
            note=" ".join(table["note"].split()) if "note" in table else None,
        )
        if network.removed is not None and network.removed < network.added:
            errors.append(f"{nctx}: 'removed' must not be before 'added'")
        entity.networks.append(network)

    sidecar = path.with_name(slug + SIDECAR_SUFFIX)
    if sidecar.exists():
        entity.networks.extend(_read_sidecar(errors, sidecar, entity.added))

    seen: set[IPNetwork] = set()
    for network in entity.networks:
        if network.cidr in seen:
            errors.append(f"{ctx}: duplicate network '{network.cidr}'")
        seen.add(network.cidr)
    if entity.active and not entity.active_networks:
        errors.append(f"{ctx}: an active entity needs at least one active network")
    return entity


def load_dataset(entities_dir: Path, tags_file: Path) -> Dataset:
    """Loads and validates the whole dataset. Raises ValidationError."""
    errors: list[str] = []
    try:
        tags = load_tags(tags_file)
    except ValidationError as e:
        errors.extend(e.errors)
        tags = {}

    entities: list[Entity] = []
    if not entities_dir.is_dir():
        raise ValidationError([f"{entities_dir}: not a directory"])
    for path in sorted(entities_dir.iterdir()):
        if path.suffix == ".toml":
            entity = _load_entity(errors, path, tags)
            if entity is not None:
                entities.append(entity)
        elif path.name.endswith(SIDECAR_SUFFIX):
            owner = path.with_name(path.name[: -len(SIDECAR_SUFFIX)] + ".toml")
            if not owner.exists():
                errors.append(f"{path}: sidecar without a matching {owner.name}")
        else:
            errors.append(f"{path}: unexpected file in entities directory")

    names: dict[str, str] = {}
    owners: dict[IPNetwork, str] = {}
    for entity in entities:
        key = entity.name.casefold()
        if key in names:
            errors.append(f"{entity.path}: name '{entity.name}' is already used by {names[key]}")
        names[key] = entity.slug
        for network in entity.networks:
            if network.cidr in owners:
                errors.append(
                    f"{entity.path}: network '{network.cidr}' is already listed by {owners[network.cidr]}"
                )
            owners[network.cidr] = entity.slug

    # Overlapping (but not identical) networks across entities are only reported.
    all_networks = [(n.cidr, e.slug) for e in entities for n in e.networks]
    for i, (a, slug_a) in enumerate(all_networks):
        for b, slug_b in all_networks[i + 1 :]:
            if slug_a != slug_b and a != b and a.version == b.version and (a.overlaps(b)):
                print(f"warning: {slug_a} '{a}' overlaps {slug_b} '{b}'", file=sys.stderr)

    if errors:
        raise ValidationError(errors)
    entities.sort(key=lambda e: (e.added, e.slug))
    return Dataset(entities=entities, tags=tags)


# --------------------------------------------------------------------------
# Text formatting (plain text -> HTML)
# --------------------------------------------------------------------------

CODE_RE = re.compile(r"`([^`\n]+)`")
URL_RE = re.compile(r"https?://[^\s<>\"']+")
URL_TRAILING = ".,;:)]}'\""


def _autolink(text: str) -> str:
    out = []
    pos = 0
    for m in URL_RE.finditer(text):
        out.append(html.escape(text[pos : m.start()]))
        url = m.group(0)
        trail = ""
        while url and url[-1] in URL_TRAILING:
            trail = url[-1] + trail
            url = url[:-1]
        out.append(f'<a href="{html.escape(url, quote=True)}">{html.escape(url)}</a>')
        out.append(html.escape(trail))
        pos = m.end()
    out.append(html.escape(text[pos:]))
    return "".join(out)


def format_inline(text: str) -> str:
    """Escapes text; `code` spans become <code>, bare URLs become links."""
    parts = CODE_RE.split(text)
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 1:
            out.append(f"<code>{html.escape(part)}</code>")
        else:
            out.append(_autolink(part))
    return "".join(out)


def format_text(text: str) -> str:
    """Formats plain text: paragraphs separated by blank lines, '- ' bullet lists."""
    blocks = re.split(r"\n[ \t]*\n", text.strip())
    out = []
    for block in blocks:
        lines = [line.rstrip() for line in block.split("\n") if line.strip()]
        if not lines:
            continue
        if lines[0].startswith("- "):
            items: list[str] = []
            for line in lines:
                if line.startswith("- "):
                    items.append(line[2:].strip())
                elif items:
                    items[-1] += " " + line.strip()
            out.append("<ul>\n" + "".join(f"<li>{format_inline(i)}</li>\n" for i in items) + "</ul>")
        else:
            out.append(f"<p>{format_inline(' '.join(line.strip() for line in lines))}</p>")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Banlist generation
# --------------------------------------------------------------------------


def banlist_rows(entities: list[Entity], default_days: int) -> list[tuple[str, int, str]]:
    """(network text, ban seconds, entity name) for every active network."""
    rows = []
    for entity in entities:
        if not entity.active:
            continue
        seconds = entity.bantime_seconds(default_days)
        for network in entity.active_networks:
            rows.append((network.text, seconds, entity.name))
    return rows


def render_banlists(rows: list[tuple[str, int, str]]) -> dict[str, str]:
    width = max((len(text) for text, _, _ in rows), default=0)
    cli = [CLI_HEADER]
    gui = []
    plain = []
    for text, seconds, name in rows:
        cli.append(f"bitcoin-cli setban {text.ljust(width)} add {seconds:<8}  # {name}")
        gui.append(f"setban {text.ljust(width)} add {seconds}")
        plain.append(text)
    return {
        OUTPUT_CLI: "\n".join(cli) + "\n",
        OUTPUT_GUI: "\n".join(gui) + "\n",
        OUTPUT_PLAIN: "\n".join(plain) + "\n",
    }


def write_banlists(dataset: Dataset, outdir: Path, default_days: int) -> None:
    rows = banlist_rows(dataset.entities, default_days)
    for name, content in render_banlists(rows).items():
        (outdir / name).write_text(content)
    print(f"wrote {len(rows)} networks to {outdir / OUTPUT_CLI}, {OUTPUT_GUI}, {OUTPUT_PLAIN}")


# --------------------------------------------------------------------------
# JSON export and schema
# --------------------------------------------------------------------------


def _iso(d: Date | None) -> str | None:
    return d.isoformat() if d is not None else None


def entity_to_json(entity: Entity, default_days: int) -> dict:
    return {
        "slug": entity.slug,
        "name": entity.name,
        "summary": entity.summary,
        "added": _iso(entity.added),
        "removed": _iso(entity.removed),
        "removed_reason": entity.removed_reason,
        "active": entity.active,
        "tags": entity.tags,
        "bantime_days": entity.bantime_days if entity.bantime_days is not None else default_days,
        "user_agents": entity.user_agents,
        "asns": entity.asns,
        "references": [
            {"url": r.url, "title": r.title, "date": _iso(r.date)} for r in entity.references
        ],
        "description": entity.description,
        "networks": [
            {
                "cidr": n.text,
                "added": _iso(n.added),
                "removed": _iso(n.removed),
                "note": n.note,
                "active": n.active,
            }
            for n in entity.networks
        ],
    }


def dataset_to_json(dataset: Dataset, default_days: int) -> dict:
    return {
        "$schema": SITE_URL + OUTPUT_SCHEMA,
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": REPO_URL,
        "default_bantime_days": default_days,
        "tags": [{"tag": t, "description": d} for t, d in dataset.tags.items()],
        "entities": [entity_to_json(e, default_days) for e in dataset.entities],
    }


_DATE = {"type": "string", "format": "date", "pattern": r"^\d{4}-\d{2}-\d{2}$"}
_NULLABLE_DATE = {"oneOf": [_DATE, {"type": "null"}]}
_NULLABLE_STR = {"type": ["string", "null"]}

JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": SITE_URL + OUTPUT_SCHEMA,
    "title": "Bitcoin banlist",
    "description": "Entities and their IP networks listed on " + SITE_URL,
    "type": "object",
    "required": ["generated", "source", "default_bantime_days", "tags", "entities"],
    "additionalProperties": False,
    "properties": {
        "$schema": {"type": "string"},
        "generated": {"type": "string", "format": "date-time"},
        "source": {"type": "string", "format": "uri"},
        "default_bantime_days": {"type": "integer", "minimum": 1},
        "tags": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tag", "description"],
                "additionalProperties": False,
                "properties": {
                    "tag": {"type": "string", "pattern": SLUG_RE.pattern},
                    "description": {"type": "string"},
                },
            },
        },
        "entities": {"type": "array", "items": {"$ref": "#/$defs/entity"}},
    },
    "$defs": {
        "entity": {
            "type": "object",
            "required": [
                "slug", "name", "summary", "added", "removed", "removed_reason", "active",
                "tags", "bantime_days", "user_agents", "asns", "references", "description",
                "networks",
            ],
            "additionalProperties": False,
            "properties": {
                "slug": {"type": "string", "pattern": SLUG_RE.pattern},
                "name": {"type": "string"},
                "summary": {"type": "string"},
                "added": _DATE,
                "removed": _NULLABLE_DATE,
                "removed_reason": _NULLABLE_STR,
                "active": {"type": "boolean"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "bantime_days": {"type": "integer", "minimum": 1},
                "user_agents": {"type": "array", "items": {"type": "string"}},
                "asns": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["asn", "name"],
                        "additionalProperties": False,
                        "properties": {
                            "asn": {"type": "integer", "minimum": 1},
                            "name": {"type": "string"},
                        },
                    },
                },
                "references": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["url", "title", "date"],
                        "additionalProperties": False,
                        "properties": {
                            "url": {"type": "string", "format": "uri"},
                            "title": {"type": "string"},
                            "date": _NULLABLE_DATE,
                        },
                    },
                },
                "description": {"type": "string"},
                "networks": {"type": "array", "items": {"$ref": "#/$defs/network"}},
            },
        },
        "network": {
            "type": "object",
            "required": ["cidr", "added", "removed", "note", "active"],
            "additionalProperties": False,
            "properties": {
                "cidr": {
                    "type": "string",
                    "description": "IPv4/IPv6 address or CIDR network. Single hosts are written without a prefix length.",
                },
                "added": _DATE,
                "removed": _NULLABLE_DATE,
                "note": _NULLABLE_STR,
                "active": {"type": "boolean"},
            },
        },
    },
}


def write_exports(dataset: Dataset, outdir: Path, default_days: int) -> None:
    (outdir / OUTPUT_JSON).write_text(json.dumps(dataset_to_json(dataset, default_days), indent=2) + "\n")
    (outdir / OUTPUT_SCHEMA).write_text(json.dumps(JSON_SCHEMA, indent=2) + "\n")
    print(f"wrote {outdir / OUTPUT_JSON} and {OUTPUT_SCHEMA}")


# --------------------------------------------------------------------------
# Website
# --------------------------------------------------------------------------


def _template(name: str) -> string.Template:
    return string.Template((TEMPLATES_DIR / name).read_text())


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _plural(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


def _chips(tags: list[str], root: str) -> str:
    return " ".join(f'<a class="tag" href="{root}#tag-{_e(t)}">{_e(t)}</a>' for t in tags)


def _networks_table(networks: list[Network], retired: bool) -> str:
    head = "<th>Network</th><th>Added</th>" + ("<th>Removed</th>" if retired else "") + "<th>Note</th>"
    rows = []
    for n in networks:
        cells = [f"<td><code>{_e(n.text)}</code></td>", f"<td>{_e(n.added)}</td>"]
        if retired:
            cells.append(f"<td>{_e(n.removed)}</td>")
        cells.append(f"<td>{format_inline(n.note) if n.note else ''}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>\n' + "\n".join(rows) + "\n</tbody></table></div>"


def render_page(title: str, description: str, canonical: str, root: str, content: str) -> str:
    return _template("base.html").substitute(
        title=_e(title),
        site_title=_e(SITE_TITLE),
        description=_e(description),
        canonical=_e(canonical),
        root=root,
        repo_url=_e(REPO_URL),
        content=content,
    )


def render_index(dataset: Dataset, default_days: int) -> str:
    active = sorted(dataset.active_entities, key=lambda e: (e.added, e.slug), reverse=True)
    removed = sorted([e for e in dataset.entities if not e.active], key=lambda e: e.removed, reverse=True)

    def row(e: Entity) -> str:
        return (
            "<tr>"
            f'<td><a href="{_e(e.slug)}/">{_e(e.name)}</a></td>'
            f"<td>{_e(e.added)}</td>"
            f"<td>{_chips(e.tags, '')}</td>"
            f'<td class="num">{len(e.active_networks)}</td>'
            f"<td>{_e(e.summary)}</td>"
            "</tr>"
        )

    entity_rows = "\n".join(row(e) for e in active) or '<tr><td colspan="5">No entities yet.</td></tr>'

    if removed:
        removed_rows = "\n".join(
            "<tr>"
            f'<td><a href="{_e(e.slug)}/">{_e(e.name)}</a></td>'
            f"<td>{_e(e.added)}</td><td>{_e(e.removed)}</td>"
            f"<td>{_e(e.removed_reason or '')}</td>"
            "</tr>"
            for e in removed
        )
        removed_section = (
            "<h2 id=\"removed\">Removed entities</h2>\n"
            "<p>These entities were removed from the banlist. Their pages are kept for reference.</p>\n"
            '<div class="table-wrap"><table><thead><tr><th>Entity</th><th>Added</th><th>Removed</th><th>Reason</th></tr></thead>'
            f"<tbody>\n{removed_rows}\n</tbody></table></div>"
        )
    else:
        removed_section = ""

    used_tags = {t for e in dataset.entities for t in e.tags}
    tag_legend = "\n".join(
        f'<dt id="tag-{_e(t)}"><span class="tag">{_e(t)}</span></dt><dd>{_e(d)}</dd>'
        for t, d in dataset.tags.items()
        if t in used_tags
    )

    network_count = sum(len(e.active_networks) for e in active)
    content = _template("index.html").substitute(
        site_description=_e(SITE_DESCRIPTION),
        entity_count=_plural(len(active), "entity", "entities"),
        network_count=_plural(network_count, "network", "networks"),
        entity_rows=entity_rows,
        removed_section=removed_section,
        tag_legend=tag_legend or "<dd>No tags in use.</dd>",
        default_bantime_days=default_days,
        repo_url=_e(REPO_URL),
        cli_file=OUTPUT_CLI,
        gui_file=OUTPUT_GUI,
        plain_file=OUTPUT_PLAIN,
        json_file=OUTPUT_JSON,
        schema_file=OUTPUT_SCHEMA,
    )
    return render_page(SITE_TITLE, SITE_DESCRIPTION, SITE_URL, "./", content)


def render_entity(entity: Entity, default_days: int) -> str:
    root = "../"
    seconds = entity.bantime_seconds(default_days)
    days = seconds // SECONDS_PER_DAY

    if entity.active:
        status = f'<span class="status active">active</span> added {_e(entity.added)}'
    else:
        status = f'<span class="status removed">removed {_e(entity.removed)}</span> added {_e(entity.added)}'
        if entity.removed_reason:
            status += f" &middot; {_e(entity.removed_reason)}"

    sections = []
    if entity.user_agents:
        items = "".join(f"<li><code>{_e(ua)}</code></li>" for ua in entity.user_agents)
        sections.append(f"<h2>User agents</h2>\n<ul>{items}</ul>")
    if entity.asns:
        items = "".join(
            f'<li><a href="https://bgp.tools/as/{a["asn"]}">AS{a["asn"]}</a> {_e(a["name"])}</li>'
            for a in entity.asns
        )
        sections.append(f"<h2>Autonomous systems</h2>\n<ul>{items}</ul>")
    if entity.references:
        items = "".join(
            f'<li><a href="{_e(r.url)}">{_e(r.title)}</a>'
            + (f' <span class="muted">({_e(r.date)})</span>' if r.date else "")
            + "</li>"
            for r in entity.references
        )
        sections.append(f"<h2>References</h2>\n<ul>{items}</ul>")

    if entity.active_networks:
        width = max(len(n.text) for n in entity.active_networks)
        setban = "\n".join(
            f"bitcoin-cli setban {n.text.ljust(width)} add {seconds}" for n in entity.active_networks
        )
        active_html = (
            f"<h2>Active networks</h2>\n{_networks_table(entity.active_networks, retired=False)}\n"
            f"<p>Ban these networks for {days} days with Bitcoin Core. These are not scripts; "
            "verify the commands before running them.</p>\n"
            f"<pre><code>{_e(setban)}</code></pre>"
        )
    elif entity.active:
        active_html = "<h2>Active networks</h2><p>None.</p>"
    else:
        active_html = "<h2>Active networks</h2><p>None. This entity was removed from the banlist.</p>"

    if entity.retired_networks:
        retired_html = f"<h2>Retired networks</h2>\n{_networks_table(entity.retired_networks, retired=True)}"
    else:
        retired_html = ""

    source_url = f"{REPO_URL}/blob/main/entities/{entity.slug}.toml"
    content = _template("entity.html").substitute(
        name=_e(entity.name),
        chips=_chips(entity.tags, root),
        status=status,
        summary=_e(entity.summary),
        description=format_text(entity.description),
        sections="\n".join(sections),
        active_networks=active_html,
        retired_networks=retired_html,
        bantime_days=days,
        source_url=_e(source_url),
    )
    return render_page(
        f"{entity.name} - {SITE_TITLE}", entity.summary, f"{SITE_URL}{entity.slug}/", root, content
    )


def write_site(dataset: Dataset, outdir: Path, default_days: int) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    write_banlists(dataset, outdir, default_days)
    write_exports(dataset, outdir, default_days)
    shutil.copy(STATIC_DIR / "style.css", outdir / "style.css")
    (outdir / ".nojekyll").write_text("")
    (outdir / "index.html").write_text(render_index(dataset, default_days))
    for entity in dataset.entities:
        page_dir = outdir / entity.slug
        page_dir.mkdir(exist_ok=True)
        (page_dir / "index.html").write_text(render_entity(entity, default_days))
    print(f"wrote index and {len(dataset.entities)} entity pages to {outdir}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="banlist", description="Validate the dataset, generate banlists and the website."
    )
    parser.add_argument("--entities", type=Path, default=DEFAULT_ENTITIES_DIR, help="entities directory")
    parser.add_argument("--tags", type=Path, default=DEFAULT_TAGS_FILE, help="tags.toml file")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="validate all entity files")

    for name, help_text in (
        ("banlist", "write banlist_cli.txt, banlist_gui.txt and banlist_plain.txt"),
        ("site", "write the website, banlists and JSON export"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("outdir", type=Path, help="output directory")
        p.add_argument(
            "--bantime-days",
            type=int,
            default=DEFAULT_BANTIME_DAYS,
            help=f"default ban duration in days for entities without bantime_days (default {DEFAULT_BANTIME_DAYS})",
        )

    args = parser.parse_args(argv)
    try:
        dataset = load_dataset(args.entities, args.tags)
    except ValidationError as e:
        for error in e.errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"{len(e.errors)} error(s)", file=sys.stderr)
        return 1

    networks = sum(len(e.networks) for e in dataset.entities)
    active = sum(len(e.active_networks) for e in dataset.active_entities)
    print(f"loaded {len(dataset.entities)} entities with {networks} networks ({active} active)")

    if args.command == "validate":
        return 0
    if args.bantime_days <= 0:
        parser.error("--bantime-days must be positive")
    args.outdir.mkdir(parents=True, exist_ok=True)
    if args.command == "banlist":
        write_banlists(dataset, args.outdir, args.bantime_days)
    elif args.command == "site":
        write_site(dataset, args.outdir, args.bantime_days)
    return 0


if __name__ == "__main__":
    sys.exit(main())
