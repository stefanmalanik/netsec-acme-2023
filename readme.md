# Project Description

ACMEv2 client project as part of the Network Security course (Fall 2023) at ETH Zürich.

Implemented according to standard specified in [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555).

## Relevant Files
- `project/source/acme_client/main.py` - ACME client implementation.
- `project/source/chall_server/main.py` - server for the HTTP challence of the ACME protocol.
- `project/source/dns_server/main.py` - DNS server for the DNS challence of the ACME protocol.
- `project/source/verif_server/main.py` - server for verifying the validity of a newly-issued certificate by performing a HTTPS query.
