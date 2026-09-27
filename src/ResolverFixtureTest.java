import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ResolverFixtureTest {

    public static void main(String[] args) throws Exception {
        InetAddress rootServer = InetAddress.getByAddress(
                new byte[]{
                        (byte) 198,
                        (byte) 41,
                        (byte) 0,
                        (byte) 4
                }
        );

        IterativeResolver.DnsExchange scriptedExchange =
                (query, server) -> {

                    String queryName =
                            DnsCodec.decodeName(query, 12).name();

                    System.out.println(
                            "SCRIPT: "
                                    + server.getHostAddress()
                                    + " asked for "
                                    + queryName
                    );

                    // Original lookup starts at root:
                    // host.example.com -> referral with no glue
                    if (server.equals(rootServer)
                            && queryName.equalsIgnoreCase("host.example.com")) {

                        return referralWithoutGlue();
                    }

                    // Helper lookup starts at root:
                    // ns1.other.net -> A 192.0.2.53
                    if (server.equals(rootServer)
                            && queryName.equalsIgnoreCase("ns1.other.net")) {

                        return nsAddressAnswer();
                    }

                    // Original lookup resumes at the resolved nameserver.
                    if (server.getHostAddress().equals("192.0.2.53")
                            && queryName.equalsIgnoreCase("host.example.com")) {

                        return finalHostAnswer();
                    }

                    throw new IOException(
                            "Unexpected scripted DNS query: "
                                    + queryName
                                    + " to "
                                    + server.getHostAddress()
                    );
                };

        IterativeResolver resolver =
                new IterativeResolver(
                        rootServer,
                        scriptedExchange
                );

        List<String> addresses =
                resolver.resolveA("host.example.com");

        System.out.println("Final addresses:");

        for (String address : addresses) {
            System.out.println(address);
        }
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeU32(ByteArrayOutputStream out, long value) {
        out.write((int) ((value >> 24) & 0xFF));
        out.write((int) ((value >> 16) & 0xFF));
        out.write((int) ((value >> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    private static void writeName(ByteArrayOutputStream out, String name) {
        String[] labels = name.split("\\.");

        for (String label : labels) {
            byte[] bytes =
                    label.getBytes(StandardCharsets.US_ASCII);

            out.write(bytes.length);
            out.writeBytes(bytes);
        }

        out.write(0);
    }

    private static byte[] referralWithoutGlue() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // HEADER
        writeU16(out, 0x1234); // ID
        writeU16(out, 0x8000); // QR = response

        writeU16(out, 1); // QDCOUNT
        writeU16(out, 0); // ANCOUNT
        writeU16(out, 1); // NSCOUNT
        writeU16(out, 0); // ARCOUNT

        // QUESTION: www.example.com A IN
        writeName(out, "www.example.com");
        writeU16(out, 1); // TYPE A
        writeU16(out, 1); // CLASS IN

        // AUTHORITY: example.com NS ns1.other.net
        writeName(out, "example.com");
        writeU16(out, 2); // TYPE NS
        writeU16(out, 1); // CLASS IN
        writeU32(out, 300); // TTL

        // Build NS RDATA separately so we know its exact length
        ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        writeName(rdata, "ns1.other.net");

        byte[] rdataBytes = rdata.toByteArray();

        writeU16(out, rdataBytes.length); // RDLENGTH
        out.writeBytes(rdataBytes);

        return out.toByteArray();
    }

    private static byte[] nsAddressAnswer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Header
        int id = 0x1234;
        int flags = 0x8400; // QR = 1, AA = 1
        int qdCount = 1;
        int anCount = 1;
        int nsCount = 0;
        int arCount = 0;

        writeU16(out, id);
        writeU16(out, flags);
        writeU16(out, qdCount);
        writeU16(out, anCount);
        writeU16(out, nsCount);
        writeU16(out, arCount);

        // Question: ns1.other.net A IN
        writeName(out, "ns1.other.net");
        writeU16(out, 1); // QTYPE = A
        writeU16(out, 1); // QCLASS = IN

        // Answer: ns1.other.net A 192.0.2.53
        writeName(out, "ns1.other.net");
        writeU16(out, 1);  // TYPE = A
        writeU16(out, 1);  // CLASS = IN
        writeU32(out, 60); // TTL = 60 seconds
        writeU16(out, 4);  // RDLENGTH = 4 bytes

        out.write(192);
        out.write(0);
        out.write(2);
        out.write(53);

        return out.toByteArray();
    }

    private static byte[] finalHostAnswer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Header
        int id = 0x1234;
        int flags = 0x8400; // QR = 1, AA = 1
        int qdCount = 1;
        int anCount = 1;
        int nsCount = 0;
        int arCount = 0;

        writeU16(out, id);
        writeU16(out, flags);
        writeU16(out, qdCount);
        writeU16(out, anCount);
        writeU16(out, nsCount);
        writeU16(out, arCount);

        // Question: host.example.com A IN
        writeName(out, "host.example.com");
        writeU16(out, 1); // QTYPE = A
        writeU16(out, 1); // QCLASS = IN

        // Answer: host.example.com A 203.0.113.7
        writeName(out, "host.example.com");
        writeU16(out, 1);  // TYPE = A
        writeU16(out, 1);  // CLASS = IN
        writeU32(out, 60); // TTL
        writeU16(out, 4);  // RDLENGTH

        out.write(203);
        out.write(0);
        out.write(113);
        out.write(7);

        return out.toByteArray();
    }
}
