# Speculator-DNS
### TLDR; A DNS server implementation written in Rust and deployed using Nix that is strictly type enforced and error handled with test cases for all functions and interfaces

## Why Speculator-DNS?
Speculator translates to scout in the context of a pathfinder in latin

## TODO:
- [ ] Error handling for all cases where `?` or unwrap() are used
- [ ] Test cases for functions
- [ ] Test cases for interfaces
- [ ] Dependency injection for tests
- [ ] Document code with cargo doc comments for v1.0.0
- [ ] Serialize logic for the following record types:
  - [ ] AFSDB
  - [ ] APL
  - [ ] DNSKEY
  - [ ] CNDSKEY
  - [ ] CERT
  - [ ] DCHID
  - [ ] DNAME
  - [ ] HIP
  - [ ] IPSEC
  - [ ] LOC
  - [ ] NAPTR
  - [ ] NSEC
  - [ ] RRSIC
  - [ ] RP
  - [ ] SSHFP
- [ ] Deserialize logic for the following record types:
  - [ ] AFSDB
  - [ ] APL
  - [ ] DNSKEY
  - [ ] CNDSKEY
  - [ ] CERT
  - [ ] DCHID
  - [ ] DNAME
  - [ ] HIP
  - [ ] IPSEC
  - [ ] LOC
  - [ ] NAPTR
  - [ ] NSEC
  - [ ] RRSIC
  - [ ] RP
  - [ ] SSHFP
- [ ] DNSSEC Support
- [ ] eDNS Support
- [ ] TCP Support
- [ ] Concurrency
- [ ] Caching
- [ ] CRUD logic for Zones
- [ ] Act as an authoritative server
### Interfaces
- [ ] CLI:v1.0.0
  - [ ] dns (Commands to manage dns server)
    - [ ] server
      - [ ] start
        - [ ] --type,-t (authoritative/cache) 
        - [ ] --records-file, -rf (read array of records from JSON file)
        - [ ] --address,-a (which address to bind the api to)
        - [ ] --port, -P (port for dns server)
      - [ ] stop  
        - [ ] --address,-a (which address the dns server is bound to)
        - [ ] --port, -P (port that dns server is running at)
    - [ ] client
      - [ ] record 
        - [ ] list
          - [ ] --record, -r
          - [ ] --all-records, -ar
          - [ ] --zone, -z
          - [ ] --all-zones, -az
        - [ ] create
          - [ ] --record, -r
          - [ ] --zone, -z
        - [ ] update
          - [ ] --record, -r
          - [ ] --zone, -z
        - [ ] remove
          - [ ] --record, -r
          - [ ] --zone, -z
  - [ ] api (Commands to manage APIs)
    - [ ] start
      - [ ] --type,-t (which api to start)
      - [ ] --address,-a (which address to bind the api to)
      - [ ] --port, -P (port for api starting)
    - [ ] stop
      - [ ] --address,-a (which address the api is bound to)
      - [ ] --port, -P (port that api is running at)
  - [ ] tui (start the tui)
  - [ ] gui (Commands to start and stop the webui)
    - [ ] start
      - [ ] --address,-a (which address the gui is bound to)
      - [ ] --port, -P (port for gui starting to run at)
    - [ ] stop
      - [ ] --address,-a (which address the gui is bound to)
      - [ ] --port, -P (port that gui is running at)
- [ ] API's protocol:ENDPOINT_CSV
  - [ ] gRPC:v1.0.0
    - [ ] record
      - [ ] create
      - [ ] read
      - [ ] update
      - [ ] delete
    - [ ] zone
      - [ ] create
      - [ ] read
      - [ ] update
      - [ ] delete
  - [ ] HTTP:v1.0.0
    - [ ] Prometheus Metric Endpoint
    - [ ] REST(JSON):v1.0.0
      - [ ] record
        - [ ] create
        - [ ] read
        - [ ] update
        - [ ] delete
      - [ ] zone
        - [ ] create
        - [ ] read
        - [ ] update
        - [ ] delete
    - [ ] REST(Hypermedia):v1.0.0
      - [ ] record
        - [ ] create
        - [ ] read
        - [ ] update
        - [ ] delete
      - [ ] zone
        - [ ] create
        - [ ] read
        - [ ] update
        - [ ] delete
- [ ] TUI
- [ ] WebUI
## DONE:
- [ x ] Serialization logic for the following record types:
  - [ x ] A
  - [ x ] CNAME
  - [ x ] AAAA
  - [ x ] MX
  - [ x ] SRV
  - [ x ] PTR
  - [ x ] CAA
  - [ x ] SOA
  - [ x ] NS
  - [ x ] TXT
- [ x ] Deserialization logic for the following record types:
  - [ x ] A
  - [ x ] CNAME
  - [ x ] AAAA
  - [ x ] MX
  - [ x ] SRV
  - [ x ] PTR
  - [ x ] CAA
  - [ x ] SOA
  - [ x ] NS
  - [ x ] TXT
- [ x ] Stub Resolver
- [ x ] Rudementary DNS Server