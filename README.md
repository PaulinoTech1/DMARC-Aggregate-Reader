# DMARC Desk

## TL;DR

A fast, private desktop viewer for DMARC aggregate reports. Point it at a folder of `.xml`/`.zip`/`.gz` reports and inspect them together; files are read in place and never uploaded. Goal: understand your email authentication posture without handing your data to a third-party service.

A fast, private desktop viewer for DMARC aggregate reports. Drop many `.xml`, `.zip`, and `.gz` reports into one folder, open that folder, and inspect them together. Files are read directly from archives and are never uploaded or extracted onto disk.

## Run

Windows: double-click `launch.bat`, or run:

```powershell
py -3 app.py
```

Python 3.10+ is recommended. No packages need to be installed.

## Features

- Batch and recursive folder scanning
- ZIP archives with one or many XML reports
- Gzip-compressed and plain XML reports
- Message-weighted DMARC pass rate
- Search and pass/fail filters
- Sortable records and a double-click detail view
- Filtered CSV export
- Background parsing so the window remains responsive
- Archive-size and unsafe XML declaration checks

DMARC passes when either the evaluated DKIM or SPF result is aligned and passes, matching aggregate-report policy evaluation semantics.

