import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class IterativeResolver {

    private final InetAddress rootServer;

    public IterativeResolver(InetAddress rootServer) {
        this.rootServer = rootServer;
    }

    public List<String> resolveA(String hostname) throws IOException {
        String currentName = hostname;
        int cnameTransitions = 0;

        InetAddress currentServer = rootServer;

        for (int hop = 0; hop < 10; hop++) {
            byte[] query = DnsCodec.encodeAQuery(currentName, 0x1234);

            System.out.println(
                    "Querying "
                            + currentServer.getHostAddress()
                            + " for "
                            + currentName
            );

            byte[] response =
                    DnsClient.exchange(query, currentServer);


            DnsMessage message =
                    DnsCodec.parseMessage(response);

            if (!message.isResponse()) {
                throw new IllegalStateException(
                        "Received packet is not a DNS response"
                );
            }

            if (message.isTruncated()) {
                throw new IllegalStateException(
                        "DNS response is truncated; TCP fallback is not supported"
                );
            }

            if (message.rcode() != 0) {
                throw new IllegalStateException(
                        "DNS server returned RCODE " + message.rcode()
                );
            }

            String answerName = currentName;

            while (true) {
                List<String> addresses = new ArrayList<>();

                for (DnsCodec.ResourceRecord rr : message.answers()) {
                    if (rr.type() == 1
                            && rr.recordClass() == 1
                            && rr.name().equalsIgnoreCase(answerName)) {

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
                            && rr.name().equalsIgnoreCase(answerName)) {

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

            if (!answerName.equalsIgnoreCase(currentName)) {
                currentName = answerName;
                currentServer = rootServer;
                continue;
            }

            InetAddress nextServer = null;

            for (DnsCodec.ResourceRecord nsRecord : message.authorities()) {
                if (nsRecord.type() != 2
                        || nsRecord.recordClass() != 1) {
                    continue;
                }

                String delegation = nsRecord.name();

                if (!isSameOrSubdomain(currentName, delegation)) {
                    continue;
                }

                DnsCodec.DecodedName target =
                        DnsCodec.decodeName(
                                response,
                                nsRecord.rdataOffset()
                        );

                String nsHostname =  DnsCodec.decodeNameRecord(response, nsRecord);

                if (!isSameOrSubdomain(nsHostname, delegation)) {
                    continue;
                }

                for (DnsCodec.ResourceRecord additional : message.additionals()) {
                    if (additional.type() == 1
                            && additional.recordClass() == 1
                            && additional.name().equalsIgnoreCase(nsHostname)) {

                        String glueIp =
                                DnsCodec.decodeARecord(response, additional);

                        nextServer = ipv4Address(glueIp);
                        break;
                    }
                }

                if (nextServer != null) {
                    break;
                }
            }

            if (nextServer == null) {
                throw new IllegalStateException(
                        "Referral contains no usable IPv4 glue"
                );
            }

            currentServer = nextServer;
        }

        throw new IllegalStateException(
                "Resolution exceeded hop limit"
        );
    }

    private static boolean isSameOrSubdomain(String name, String zone) {
        String n = name.toLowerCase();
        String z = zone.toLowerCase();

        return n.equals(z) || n.endsWith("." + z);
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
}