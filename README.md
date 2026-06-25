# banlist

An optional, centralized, and incomplete banlist containing the IP
addresses of possibly malicious entities on the Bitcoin network.

## Using the list

The `banlist_cli.txt` file contains `bitcoin-cli` commands to ban the the IP
addresses on the list for one year. Similarly, the commands in `banlist_gui.txt`
can be used in the console tab of the Bitcoin Core GUI. The `banlist_plain.txt`
file contains only the IP addresses. **Note: Always check files downloaded from
the internet for malicous commands first before using them. These files are not
scripts.**.

## Generating the lists

The lists can be generated with the Python tool in `contrib/gen-banlist/`.

## Adding an entity

When adding a new entity, please provide detailed information about the entity's
behavior and why you think the entity is malicious.

The `entities.toml` file contains a list of entities and their IP addresses that
could be mallicious actors on the Bitcoin network. Each entity has a `name`,
a `description`, a date `added`, a list of `tags`, and a list of `ips`. The
`name` should be unique and related to the entity or its actions. Someone
searching for the entity name should be able to find the name in this banlist.
The `description` should contain information about the entity and why it's on
this banlist. The description should be in MarkDown and can contain links to
further information on the entity or its activities. The `added` date should be
in the YYYY-MM-DD format. The list of `tags` describes the activity of the
entity. When possible, existing tags should be reused when adding a new entity.
The list of `ips` can contain either single IP addreses (IPv4, IPv6) like
`208.67.222.222` or IP address ranges (IPv4 and IPv6) like `208.67.222.0/24`.
Also check `ips/` for entities with a large number of individual IP addresses.

```TOML
[[entities]]
name = "Unique name"
added = 2009-01-03
tags = [
  "tag1",
  "tag2",
]
description = """
This is a **MarkDown** description.
"""
ips = [
  "208.67.222.222",
  "208.67.222.0/24",
]

```

