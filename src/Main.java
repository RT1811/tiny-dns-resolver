import java.io.IOException;
import java.net.InetAddress;

public class Main {
    public static void main(String[] args) throws IOException {
        byte[] query = DnsCodec.encodeAQuery(
                "ubc.ca",
                0x1234
        );

        InetAddress rootServer = InetAddress.getByAddress(
                new byte[]{
                        (byte) 198,
                        (byte) 41,
                        (byte) 0,
                        (byte) 4
                }
        );

        byte[] response = DnsClient.exchange(query, rootServer);

        System.out.println("Received " + response.length + " bytes");

        DnsMessage message = DnsCodec.parseMessage(response);

        if (!message.isResponse()) {
            throw new IllegalArgumentException("Received DNS packet is not a response");
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

        System.out.println("ID: " + message.id());
        System.out.println("Flags: " + message.flags());
        System.out.println("Answers: " + message.answers().size());
        System.out.println("Authorities: " + message.authorities().size());
        System.out.println("Additionals: " + message.additionals().size());

        DnsCodec.ResourceRecord rr = message.authorities().get(0);

        System.out.println(rr.name() + " type=" + rr.type());

        System.out.println("Response: " + message.isResponse());
        System.out.println("Truncated: " + message.isTruncated());
        System.out.println("RCODE: " + message.rcode());

        DnsCodec.ResourceRecord nsRecord = message.authorities().get(0);

        DnsCodec.DecodedName nsTarget =
                DnsCodec.decodeName(
                        response,
                        nsRecord.rdataOffset()
                );

        System.out.println("Selected NS: " + nsTarget.name());

        String glueIp = "";

        for (DnsCodec.ResourceRecord additional : message.additionals()) {
            if (additional.type() == 1 && additional.name().equalsIgnoreCase(nsTarget.name())) {

                glueIp = DnsCodec.decodeARecord(response, additional);

                System.out.println("Matching glue: " + glueIp);
                break;
            }
        }

        String[] parts = glueIp.split("\\.");

        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address");
        }

        byte[] addressBytes = new byte[4];

        for (int i = 0; i < 4; i++) {
            int value = Integer.parseInt(parts[i]);

            if (value < 0 || value > 255) {
                throw new IllegalArgumentException("Invalid IPv4 octet");
            }

            addressBytes[i] = (byte) value;
        }

        InetAddress nextServer =
                InetAddress.getByAddress(addressBytes);

        byte[] nextResponse =
                DnsClient.exchange(query, nextServer);

        DnsMessage nextMessage =
                DnsCodec.parseMessage(nextResponse);

        for (DnsCodec.ResourceRecord rr2 : nextMessage.authorities()) {
            if (rr2.type() == 2) {
                DnsCodec.DecodedName target =
                        DnsCodec.decodeName(nextResponse, rr2.rdataOffset());

                System.out.println("NS: " + target.name());
            }
        }

        for (DnsCodec.ResourceRecord rr2 : nextMessage.additionals()) {
            if (rr2.type() == 1) {
                System.out.println(
                        "A: " + rr2.name()
                                + " -> "
                                + DnsCodec.decodeARecord(nextResponse, rr2)
                );
            }
        }

        System.out.println("Queried next server: "
                + nextServer.getHostAddress());

        System.out.println("Answers: "
                + nextMessage.answers().size());

        System.out.println("Authorities: "
                + nextMessage.authorities().size());

        System.out.println("Additionals: "
                + nextMessage.additionals().size());

        System.out.println("Truncated: "
                + nextMessage.isTruncated());

        System.out.println("RCODE: "
                + nextMessage.rcode());

        System.out.println(
                "Authoritative: " + nextMessage.isAuthoritative()
        );

        DnsCodec.ResourceRecord nextNsRecord =
                nextMessage.authorities().get(0);

        DnsCodec.DecodedName nextNsTarget =
                DnsCodec.decodeName(
                        nextResponse,
                        nextNsRecord.rdataOffset()
                );

        System.out.println("Next selected NS: " + nextNsTarget.name());

        String nextGlueIp = null;

        for (DnsCodec.ResourceRecord additional : nextMessage.additionals()) {
            if (additional.type() == 1
                    && additional.name().equalsIgnoreCase(nextNsTarget.name())) {

                nextGlueIp =
                        DnsCodec.decodeARecord(nextResponse, additional);

                System.out.println("Next matching glue: " + nextGlueIp);
                break;
            }
        }

        InetAddress authoritativeServer = InetAddress.getByAddress(
                new byte[]{
                        (byte) 137,
                        (byte) 82,
                        (byte) 1,
                        (byte) 1
                }
        );

        byte[] finalResponse =
                DnsClient.exchange(query, authoritativeServer);

        DnsMessage finalMessage =
                DnsCodec.parseMessage(finalResponse);

        System.out.println(
                "Queried authoritative server: "
                        + authoritativeServer.getHostAddress()
        );

        System.out.println("Answers: "
                + finalMessage.answers().size());

        System.out.println("Authorities: "
                + finalMessage.authorities().size());

        System.out.println("Additionals: "
                + finalMessage.additionals().size());

        System.out.println("Authoritative: "
                + finalMessage.isAuthoritative());

        System.out.println("Truncated: "
                + finalMessage.isTruncated());

        System.out.println("RCODE: "
                + finalMessage.rcode());

        for (DnsCodec.ResourceRecord rr1 : finalMessage.answers()) {
            System.out.println(
                    "ANSWER: " + rr1.name()
                            + " type=" + rr1.type()
            );

            if (rr1.type() == 1) {
                System.out.println(
                        "IPv4: "
                                + DnsCodec.decodeARecord(finalResponse, rr1)
                );
            }
        }
    }
}