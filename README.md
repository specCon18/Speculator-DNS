# Speculator-DNS
### TLDR; A DNS server implementation written in Rust and deployed using Nix that is strictly type enforced and error handled with test cases for all functions and interfaces with a focus on implementation as a library for other projects interfacing with DNS

## Why Speculator-DNS?
Speculator translates to scout in the context of a pathfinder in latin

##Roadmap
The project kanban can be found [here](https://tree.taiga.io/project/speccon18-speculator-dns/kanban)

## Features:
- Serialization logic for the following record types:
  - A
  - CNAME
  - AAAA
  - MX
  - SRV
  - PTR
  - CAA
  - SOA
  - NS
  - TXT
- Deserialization logic for the following record types:
  - A
  - CNAME
  - AAAA
  - MX
  - SRV
  - PTR
  - CAA
  - SOA
  - NS
  - TXT
- Stub Resolver
- Rudementary DNS Server
- Recursive Resolution

# Credits
Huge thanks to [EmilHernvall](https://github.com/EmilHernvall/) for his [dnsguide](https://github.com/EmilHernvall/dnsguide) I wouldn't have known where to start without it!
