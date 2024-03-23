# Speculator-DNS
### TLDR; A DNS server implementation written in Rust and deployed using Nix that is strictly type enforced and error handled with test cases for all functions and interfaces

## Why Speculator-DNS?
Speculator translates to scout in the context of a pathfinder in latin

## [Roadmap](https://tree.taiga.io/project/speccon18-speculator-dns/kanban)
### Interfaces
-  CLI:v1.0.0
  -  dns (Commands to manage dns server)
    -  server
      -  start
        -  --type,-t (authoritative/cache) 
        -  --records-file, -rf (read array of records from JSON file)
        -  --address,-a (which address to bind the api to)
        -  --port, -P (port for dns server)
      -  stop  
        -  --address,-a (which address the dns server is bound to)
        -  --port, -P (port that dns server is running at)
    -  client
      -  record 
        -  list
          -  --record, -r
          -  --all-records, -ar
          -  --zone, -z
          -  --all-zones, -az
        -  create
          -  --record, -r
          -  --zone, -z
        -  update
          -  --record, -r
          -  --zone, -z
        -  remove
          -  --record, -r
          -  --zone, -z
  -  api (Commands to manage APIs)
    -  start
      -  --type,-t (which api to start)
      -  --address,-a (which address to bind the api to)
      -  --port, -P (port for api starting)
    -  stop
      -  --address,-a (which address the api is bound to)
      -  --port, -P (port that api is running at)
  -  tui (start the tui)
  -  gui (Commands to start and stop the webui)
    -  start
      -  --address,-a (which address the gui is bound to)
      -  --port, -P (port for gui starting to run at)
    -  stop
      -  --address,-a (which address the gui is bound to)
      -  --port, -P (port that gui is running at)
-  API's protocol:version
  -  gRPC:v1.0.0
    -  record
      -  create
      -  read
      -  update
      -  delete
    -  zone
      -  create
      -  read
      -  update
      -  delete
  -  HTTP:v1.0.0
    -  Prometheus Metric Endpoint
    -  REST(JSON):v1.0.0
      -  record
        -  create
        -  read
        -  update
        -  delete
      -  zone
        -  create
        -  read
        -  update
        -  delete
    -  REST(Hypermedia):v1.0.0
      -  record
        -  create
        -  read
        -  update
        -  delete
      -  zone
        -  create
        -  read
        -  update
        -  delete
-  TUI
-  WebUI
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
