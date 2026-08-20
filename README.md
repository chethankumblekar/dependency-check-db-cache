# Dependency Check DB Cache

This repository automatically downloads and updates the OWASP Dependency-Check vulnerability database and publishes it as a GitHub Release.

## Purpose

The initial NVD synchronization performed by OWASP Dependency-Check can take a long time and may fail because of:

- NVD API throttling
- Network restrictions
- CI/CD timeout limits

This project generates an updated database daily and publishes it as a release artifact.

## Usage

Download latest release:

```bash
dependency-check-db.zip
```

Extract and use:

```bash
dependency-check.sh \
  --scan . \
  --data ./dependency-check-data \
  --noupdate
```
