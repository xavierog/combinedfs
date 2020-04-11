# CombinedFS

CombinedFS stands for Completely Over-engineered, Melted Brain-Induced, Not Even Decent Fucking Solution.
Well, no, it doesn't, but I like far-fetched acronyms.

CombinedFS is a FUSE FileSystem that exposes a transformed, straightforward, read-only version of Let's Encrypt / Certbot's "live" directory for better integration with software that requires "combined" PEM files.

## Features

 - Dynamically concatenate and expose adequate PEM files;
 - include PEM files from outside the Certbot directory, e.g. Diffie-Hellman parameters;
 - hide symlinks, resulting in a single directory to expose to your TLS frontend;
 - filter exposed certificates (whitelist / blacklist) using a regular expression;
 - expose either a Certbot-like tree (e.g. my.domain.tld/combined.pem), suitable for those who just need filtering or concatenation...
 - or a flattened directory (e.g. my.domain.tld_cert.pem), suitable for software that loads all PEM files in a given directory;
 - specify Unix permissions: uid, gid, mode, either globally or on a per-file basis (not a per-cert basis though).

## Implementation

 - Python with [fusepy](https://github.com/fusepy/fusepy)
 - YAML/JSON configuration file

## How to use it

```
combinedfs.py [--foreground] /path/to/configuration.yaml /mount/point
```

fstab syntax:
```
/path/to/configuration.yaml    /mount/point    fuse.combinedfs    defaults    0 0
```

Refer to `configuration.reference.yaml` to write your own configuration file.

It is possible to reload the configuration file without remounting the filesystem.
```
cat /mount/point/reload
```
This will output either "reload ok" or "reload fail".

## Why?

Certbot already offers hooks to handle pretty much everything, from mere concatenations to complex deployments to various kinds of clusters.
So why write a Fuse FileSystem to cover only a small part of this scope?
Well, duh. Because it's fun, here's why.
