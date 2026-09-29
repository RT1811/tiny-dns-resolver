# Tiny Iterative DNS Resolver

A small iterative DNS resolver written from scratch in Java.

The resolver constructs and parses DNS packets directly, starts from a numeric root-server IP address, follows DNS delegations iteratively, handles CNAMEs and missing glue records, and returns IPv4 `A` records without relying on the operating system's recursive DNS resolver.

The project was built primarily to understand what actually happens underneath a normal DNS lookup: DNS wire format, name compression, referrals, glue records, recursive dependencies between nameserver lookups, UDP behavior, and the failure cases that appear when working directly with protocol bytes.

## Features

- Constructs DNS `A` queries manually
- Sends DNS queries over UDP
- Starts resolution from a numeric root-server IP
- Parses DNS headers and all three resource-record sections
- Decodes normal DNS names and compressed names
- Parses generic resource records using `RDLENGTH`
- Decodes:
    - `A`
    - `NS`
    - `CNAME`
- Safely skips unsupported resource-record types
- Follows iterative DNS referrals
- Uses in-delegation IPv4 glue records
- Resolves nameserver addresses when glue is unavailable
- Follows CNAME chains
- Restarts resolution from the root when a CNAME points into another DNS hierarchy
- Tries an alternate nameserver if the primary server fails
- Rejects referrals that do not advance the delegation
- Handles terminal DNS errors such as:
    - `NXDOMAIN`
    - `SERVFAIL`
    - authoritative responses with no usable `A` record
- Detects truncated UDP responses
- Applies bounded lookup depth, query count, CNAME transitions, and total lookup time
- Validates DNS responses before accepting them

## Example

A lookup for `ubc.ca`:

```text
Querying 198.41.0.4 for ubc.ca
Using glue: d.ca-servers.ca -> 45.142.220.101
Using alternate glue: any.ca-servers.ca -> 199.4.144.2
Querying 45.142.220.101 for ubc.ca
Using glue: hub.ubc.ca -> 137.82.1.1
Using alternate glue: dns3.ubc.ca -> 142.103.1.1
Querying 137.82.1.1 for ubc.ca
Resolved addresses:
52.223.56.149
```

The path corresponds to the normal iterative DNS process:

```text
Root server
    ↓
.ca nameserver
    ↓
ubc.ca authoritative nameserver
    ↓
A record
```

DNS records are live data, so the nameservers and addresses shown above may change over time.

## Missing Glue Resolution

A delegation does not always provide an IPv4 address for the nameserver it references.

For example:

```text
example.com NS ns1.other.net
```

If no usable `A` record for `ns1.other.net` is included in the Additional section, the resolver temporarily pauses the original lookup and resolves the nameserver hostname itself:

```text
host.example.com
        ↓
example.com NS ns1.other.net
        ↓
no usable glue
        ↓
resolve ns1.other.net
        ↓
192.0.2.53
        ↓
resume host.example.com lookup
```

Helper lookups use the same resolver and share the original lookup's query budget, deadline, and cycle detection.

## CNAME Handling

The resolver follows CNAME chains before processing referrals or treating a response as negative.

For example:

```text
www.ubc.ca
    ↓
CNAME
    ↓
d3tie7xuvq1kvm.cloudfront.net
```

If the response already contains the target's `A` record, it can be returned immediately.

Otherwise, resolution restarts from the root for the new hostname.

CNAME transitions are bounded so an alias loop cannot run forever.

## Nameserver Fallback

When a referral contains multiple usable IPv4 nameservers, the resolver keeps both a primary and an alternate candidate.

For example:

```text
example.com NS ns1.example.com
example.com NS ns2.example.com

ns1.example.com A 192.0.2.10
ns2.example.com A 192.0.2.11
```

If the first server fails:

```text
Querying 192.0.2.10 for host.example.com
Nameserver 192.0.2.10 failed; trying 192.0.2.11
Querying 192.0.2.11 for host.example.com
```

The resolver continues using the alternate instead of terminating the lookup immediately.

## DNS Response Validation

Responses are not accepted solely because a UDP datagram arrived.

The resolver checks:

- UDP peer/server
- transaction ID
- response (`QR`) bit
- DNS opcode
- echoed question count
- echoed hostname
- echoed query type
- echoed query class
- truncation (`TC`)
- DNS response code (`RCODE`)
- packet and resource-record boundaries

Malformed or unrelated responses are rejected rather than partially processed.

## Defensive Bounds

Direct protocol implementations need explicit termination rules.

The resolver includes bounds for:

- total DNS queries
- total lookup duration
- iterative referral hops
- CNAME transitions
- recursive nameserver-address lookup depth
- active helper-lookup cycles
- DNS compression-pointer cycles

A referral must also advance to a more specific delegation before it is followed.

## DNS Packet Parsing

DNS names are encoded as a sequence of labels:

```text
example.com
```

becomes conceptually:

```text
07 example 03 com 00
```

DNS responses may replace part or all of a name with a compression pointer. The decoder therefore keeps two separate positions:

- the position currently being followed while decoding the name
- the position immediately after the encoded name in the original packet

This allows compressed names to be decoded correctly without losing the offset needed to continue parsing the surrounding DNS structure.

Resource records are parsed generically as:

```text
NAME
TYPE
CLASS
TTL
RDLENGTH
RDATA
```

The generic parser advances using the declared `RDLENGTH`; record-specific decoders interpret the RDATA afterward.

## Project Structure

```text
src/
├── Main.java
├── DnsClient.java
├── DnsCodec.java
├── DnsMessage.java
├── IterativeResolver.java
└── ResolverFixtureTest.java
```

### `DnsCodec`

Responsible for DNS wire-format operations:

- query encoding
- unsigned integer decoding
- DNS-name decoding
- compression-pointer handling
- resource-record parsing
- `A`, `NS`, and `CNAME` RDATA decoding

### `DnsClient`

Handles UDP communication with DNS servers.

The UDP socket is connected to the target server and port so responses from unrelated endpoints are not accepted.

### `DnsMessage`

Represents a parsed DNS message:

- header fields
- Answer records
- Authority records
- Additional records
- flag helpers such as `isResponse()`, `isAuthoritative()`, `isTruncated()`, `opcode()`, and `rcode()`

### `IterativeResolver`

Implements the resolution algorithm:

- begins at the root
- validates responses
- follows referrals
- selects trusted glue
- resolves nameserver hostnames when necessary
- follows CNAMEs
- retries an alternate nameserver
- tracks delegation progress
- enforces lookup bounds

### `ResolverFixtureTest`

Contains deterministic, synthetic DNS packets used to test protocol behavior without depending on live DNS infrastructure.

## Deterministic Tests

The fixture suite currently covers:

```text
Truncated record
Wrong transaction ID
Wrong echoed question
Wrong opcode
Missing-glue resolution
Repeated referral
CNAME loop
Nameserver fallback
```

Example output:

```text
=== Truncated record ===
PASS: DNS RDATA extends beyond packet

=== Wrong transaction ID ===
PASS: DNS transaction ID mismatch

=== Wrong echoed question ===
PASS: DNS response echoed the wrong hostname

=== Wrong opcode ===
PASS: Unsupported DNS opcode 1

=== Missing glue resolution ===
PASS: resolved to 203.0.113.7

=== Repeated referral ===
PASS: Referral contains no usable IPv4 nameserver

=== CNAME loop ===
PASS: CNAME chain exceeded limit

=== Nameserver fallback ===
PASS: fallback resolved to 203.0.113.7
```

Synthetic tests use documentation-only address ranges such as `192.0.2.0/24` and `203.0.113.0/24`; no real DNS servers are contacted by those tests.

## Live Testing

The resolver has successfully completed iterative live resolutions including:

### `ubc.ca`

```text
Root
→ .ca
→ ubc.ca authoritative server
→ A record
```

The resolver's delegation path was manually compared against non-recursive DNS queries and matched the corresponding Authority and Additional records.

### `iana.org`

This lookup exercised a more complicated path:

```text
Root
→ .org
→ missing nameserver address
→ helper nameserver lookup
→ some helper candidates return truncated responses
→ another nameserver candidate succeeds
→ resume original lookup
→ final A record
```

Example final result:

```text
Resolved addresses:
192.0.43.8
```

Again, live DNS data may change over time.

## Building and Running

The project has no external runtime dependencies.

Compile from the project root:

```powershell
javac -d out src\*.java
```

Run the resolver:

```powershell
java -cp out Main
```

Run the deterministic fixture suite:

```powershell
java -cp out ResolverFixtureTest
```

The project can also be run directly from IntelliJ IDEA.

## Hostname Input

The resolver accepts ASCII DNS names with or without a trailing root dot:

```text
www.ubc.ca
www.ubc.ca.
```

Both encode to the same DNS QNAME.

Malformed names are rejected, including:

```text
.www.ubc.ca
www..ubc.ca
```

The encoder also rejects:

- empty names
- empty labels
- non-ASCII input
- labels longer than 63 bytes
- encoded DNS names longer than 255 bytes

## Limitations

This is intentionally a small educational resolver rather than a production DNS implementation.

It currently supports:

```text
IPv4 A resolution
UDP DNS
iterative resolution
NS referrals
IPv4 glue
CNAMEs
```

It intentionally does **not** implement:

- TCP fallback for truncated responses
- EDNS
- DNSSEC validation
- IPv6 `AAAA` resolution
- caching
- negative caching
- parallel nameserver queries
- a full recursive-resolver service
- every DNS resource-record type

If a response has the DNS `TC` flag set, the resolver reports that TCP fallback is unsupported rather than using partial data from the truncated response.

## Why Build This?

Normally, DNS resolution is hidden behind APIs such as:

```java
InetAddress.getByName(...)
```

That abstraction is useful, but it hides most of the protocol.

Building a small resolver directly exposed several details that are easy to miss when only using high-level networking APIs:

- DNS packet fields are byte-level protocol structures.
- Name compression changes how parser offsets must be tracked.
- Authority records identify the next nameserver, but do not necessarily provide its address.
- Glue records must be associated with the correct delegation.
- Resolving a nameserver can itself require another iterative DNS lookup.
- UDP responses must be validated before their contents are trusted.
- Real DNS servers can return truncated responses even for ordinary lookups.
- Correct termination behavior is as important as the happy path.

The goal of the project is not to replace a production recursive resolver, but to make the mechanics of iterative DNS resolution concrete by implementing them directly.

<img width="4152" height="5938" alt="diagram" src="https://github.com/user-attachments/assets/7c9d6523-926d-48bd-80d8-df337d90ee47" />
