import java.io.IOException;
import java.net.InetAddress;
import java.util.*;

public class IterativeResolver {

    private final InetAddress rootServer;
    private final DnsExchange exchange;

    public IterativeResolver(InetAddress rootServer) {
        this.rootServer = rootServer;
        this.exchange = DnsClient::exchange;
    }

    public IterativeResolver(
            InetAddress rootServer,
            DnsExchange exchange
    ) {
        this.rootServer = rootServer;
        this.exchange = exchange;
    }

    @FunctionalInterface
    public interface DnsExchange {
        byte[] exchange(byte[] query, InetAddress server) throws IOException;
    }

    private static class LookupContext {
        int queriesRemaining = 40;
        final Set<String> activeLookups = new HashSet<>();
        final long deadlineNanos = System.nanoTime() + 30_000_000_000L;
    }

    public List<String> resolveA(String hostname) throws IOException {
        LookupContext context = new LookupContext();

        return resolveA(normalizeName(hostname), context, 0);
    }

    private List<String> resolveA(String hostname,
                                  LookupContext context,
                                  int helperDepth
    ) throws IOException {
        if (helperDepth > 6) {
            throw new IllegalStateException(
                    "Nameserver helper lookup depth exceeded"
            );
        }

        String lookupKey = hostname.toLowerCase();

        if (!context.activeLookups.add(lookupKey)) {
            throw new IllegalStateException(
                    "DNS lookup cycle detected for " + hostname
            );
        }

        try {
            String currentName = hostname;
            int cnameTransitions = 0;

            InetAddress currentServer = rootServer;

            String currentDelegation = null;
            String selectedDelegation = null;

            for (int hop = 0; hop < 10; hop++) {
                byte[] query = DnsCodec.encodeAQuery(currentName, 0x1234);

                System.out.println(
                        "Querying "
                                + currentServer.getHostAddress()
                                + " for "
                                + currentName
                );

                if (System.nanoTime() >= context.deadlineNanos) {
                    throw new IllegalStateException(
                            "DNS lookup deadline exceeded"
                    );
                }

                if (context.queriesRemaining <= 0) {
                    throw new IllegalStateException(
                            "DNS query budget exhausted"
                    );
                }

                context.queriesRemaining--;

                byte[] response = exchange.exchange(query, currentServer);

                DnsMessage message = DnsCodec.parseMessage(response);

                int expectedId = DnsCodec.readU16(query, 0);

                if (message.id() != expectedId) {
                    throw new IllegalStateException(
                            "DNS transaction ID mismatch"
                    );
                }

                if (!message.isResponse()) {
                    throw new IllegalStateException(
                            "Received packet is not a DNS response"
                    );
                }

                if (message.opcode() != 0) {
                    throw new IllegalStateException(
                            "Unsupported DNS opcode " + message.opcode()
                    );
                }

                if (message.isTruncated()) {
                    throw new IllegalStateException(
                            "DNS response is truncated; TCP fallback is not supported"
                    );
                }

                if (message.rcode() == 3) {
                    throw new IllegalStateException(
                            "NXDOMAIN: " + currentName + " does not exist"
                    );
                }

                if (message.rcode() == 2) {
                    throw new IllegalStateException(
                            "SERVFAIL while resolving " + currentName
                    );
                }

                if (message.rcode() != 0) {
                    throw new IllegalStateException(
                            "DNS server returned unsupported RCODE "
                                    + message.rcode()
                    );
                }

                validateEchoedQuestion(response, message, currentName);

                String answerName = currentName;

                while (true) {
                    List<String> addresses = new ArrayList<>();

                    for (DnsCodec.ResourceRecord rr : message.answers()) {
                        if (rr.type() == 1
                                && rr.recordClass() == 1
                                && normalizeName(rr.name()).equals(normalizeName(answerName))) {

                            addresses.add(
                                    DnsCodec.decodeARecord(response, rr)
                            );
                        }
                    }

                    if (!addresses.isEmpty()) {
                        return addresses;
                    }

                    String cnameTarget = null;

                    for (DnsCodec.ResourceRecord rr : message.answers()) {
                        if (rr.type() == 5
                                && rr.recordClass() == 1
                                && normalizeName(rr.name()).equals(normalizeName(answerName))) {

                            cnameTarget =
                                    DnsCodec.decodeNameRecord(response, rr);

                            break;
                        }
                    }

                    if (cnameTarget == null) {
                        break;
                    }

                    cnameTransitions++;

                    if (cnameTransitions > 8) {
                        throw new IllegalStateException(
                                "CNAME chain exceeded limit"
                        );
                    }

                    System.out.println(
                            "CNAME: " + answerName + " -> " + cnameTarget
                    );

                    answerName = cnameTarget;
                }

                if (!normalizeName(answerName).equals(normalizeName(currentName))) {
                    currentName = answerName;
                    currentServer = rootServer;

                    currentDelegation = null;
                    selectedDelegation = null;

                    continue;
                }

                if (message.isAuthoritative()) {
                    throw new IllegalStateException(
                            "Authoritative response contains no A record for "
                                    + currentName
                    );
                }

                InetAddress nextServer = null;

                for (DnsCodec.ResourceRecord nsRecord : message.authorities()) {
                    if (nsRecord.type() != 2
                            || nsRecord.recordClass() != 1) {
                        continue;
                    }

                    String delegation = nsRecord.name();

                    if (currentDelegation != null
                            && !isStrictSubdomain(
                            delegation,
                            currentDelegation
                    )) {
                        continue;
                    }

                    if (!isSameOrSubdomain(currentName, delegation)) {
                        continue;
                    }

                    String nsHostname =
                            DnsCodec.decodeNameRecord(response, nsRecord);

                    if (!isSameOrSubdomain(nsHostname, delegation)) {
                        continue;
                    }

                    for (DnsCodec.ResourceRecord additional : message.additionals()) {
                        if (additional.type() == 1
                                && additional.recordClass() == 1
                                && normalizeName(additional.name()).equals(normalizeName(nsHostname))) {

                            String glueIp =
                                    DnsCodec.decodeARecord(response, additional);

                            nextServer = ipv4Address(glueIp);
                            selectedDelegation = delegation;

                            System.out.println(
                                    "Using glue: "
                                            + nsHostname
                                            + " -> "
                                            + glueIp
                            );

                            break;
                        }
                    }

                    if (nextServer != null) {
                        break;
                    }
                }

                if (nextServer == null) {
                    for (DnsCodec.ResourceRecord nsRecord : message.authorities()) {
                        if (nsRecord.type() != 2
                                || nsRecord.recordClass() != 1) {
                            continue;
                        }

                        String delegation = nsRecord.name();

                        if (currentDelegation != null
                                && !isStrictSubdomain(
                                delegation,
                                currentDelegation
                        )) {
                            continue;
                        }

                        if (!isSameOrSubdomain(currentName, delegation)) {
                            continue;
                        }

                        String nsHostname =
                                DnsCodec.decodeNameRecord(response, nsRecord);

                        if (isSameOrSubdomain(nsHostname, delegation)) {
                            continue;
                        }

                        try {
                            List<String> nsAddresses =
                                    resolveA(
                                            nsHostname,
                                            context,
                                            helperDepth + 1
                                    );

                            if (!nsAddresses.isEmpty()) {
                                nextServer =
                                        ipv4Address(nsAddresses.get(0));
                                selectedDelegation = delegation;

                                System.out.println(
                                        "Resolved NS address: "
                                                + nsHostname
                                                + " -> "
                                                + nsAddresses.get(0)
                                );

                                break;
                            }
                        }  catch (IllegalStateException e) {
                            if ("DNS query budget exhausted".equals(e.getMessage())
                                    || "DNS lookup deadline exceeded".equals(e.getMessage())) {
                                throw e;
                            }

                            System.out.println(
                                    "Could not resolve nameserver "
                                            + nsHostname
                                            + ": "
                                            + e.getMessage()
                            );

                            System.out.println(
                                    "Could not resolve nameserver "
                                            + nsHostname
                                            + ": "
                                            + e.getMessage()
                            );
                        } catch (IOException e) {
                            System.out.println(
                                    "Could not resolve nameserver "
                                            + nsHostname
                                            + ": "
                                            + e.getMessage()
                            );
                        }
                    }
                }

                if (nextServer == null) {
                    throw new IllegalStateException(
                            "Referral contains no usable IPv4 nameserver"
                    );
                }

                currentDelegation = selectedDelegation;
                currentServer = nextServer;
            }

            throw new IllegalStateException(
                    "Resolution exceeded hop limit"
            );
        } finally {
            context.activeLookups.remove(lookupKey);
        }
    }

    private static boolean isSameOrSubdomain(String name, String zone) {
        String n = normalizeName(name);
        String z = normalizeName(zone);


        return n.equals(z) || n.endsWith("." + z);
    }

    private static boolean isStrictSubdomain(String name, String parent) {
        String n = normalizeName(name);
        String p = normalizeName(parent);

        return !n.equals(p)
                && n.endsWith("." + p);
    }

    private static InetAddress ipv4Address(String ip) throws IOException {
        String[] ipv4 = ip.split("\\.");
        return InetAddress.getByAddress(
                new byte[]{
                        (byte) Integer.parseInt(ipv4[0]),
                        (byte) Integer.parseInt(ipv4[1]),
                        (byte) Integer.parseInt(ipv4[2]),
                        (byte) Integer.parseInt(ipv4[3])
                }
        );
    }

    private static void validateEchoedQuestion(
            byte[] response,
            DnsMessage message,
            String expectedName
    ) {
        if (message.qdCount() != 1) {
            throw new IllegalStateException(
                    "DNS response has unexpected question count"
            );
        }

        DnsCodec.DecodedName questionName =
                DnsCodec.decodeName(response, 12);

        if (!questionName.name().equalsIgnoreCase(expectedName)) {
            throw new IllegalStateException(
                    "DNS response echoed the wrong hostname"
            );
        }

        int offset = questionName.nextOffset();

        int qtype = DnsCodec.readU16(response, offset);
        offset += 2;

        int qclass = DnsCodec.readU16(response, offset);

        if (qtype != 1) {
            throw new IllegalStateException(
                    "DNS response echoed the wrong query type"
            );
        }

        if (qclass != 1) {
            throw new IllegalStateException(
                    "DNS response echoed the wrong query class"
            );
        }
    }

    private static String normalizeName(String name) {
        String normalized = name.toLowerCase(Locale.ROOT);

        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        return normalized;
    }
}