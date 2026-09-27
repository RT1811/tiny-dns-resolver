import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ResolverFixtureTest {

    public static void main(String[] args) throws Exception {
        testTruncatedRecordRejected();
        testWrongTransactionIdRejected();
        testWrongQuestionRejected();
        testWrongOpcodeRejected();
        testMissingGlueResolution();
        testRepeatedReferralRejected();
        testCnameLoopRejected();
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
        writeName(out, "host.example.com");
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

    private static byte[] cnameLoopAnswer() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Header
        int id = 0x1234;
        int flags = 0x8400; // QR = 1, AA = 1
        int qdCount = 1;
        int anCount = 2;
        int nsCount = 0;
        int arCount = 0;

        writeU16(out, id);
        writeU16(out, flags);
        writeU16(out, qdCount);
        writeU16(out, anCount);
        writeU16(out, nsCount);
        writeU16(out, arCount);

        // Question: a.test A IN
        writeName(out, "a.test");
        writeU16(out, 1); // QTYPE = A
        writeU16(out, 1); // QCLASS = IN

        // Answer 1: a.test CNAME b.test
        writeName(out, "a.test");
        writeU16(out, 5);  // TYPE = CNAME
        writeU16(out, 1);  // CLASS = IN
        writeU32(out, 60); // TTL

        ByteArrayOutputStream cname1Rdata =
                new ByteArrayOutputStream();

        writeName(cname1Rdata, "b.test");

        byte[] cname1Bytes = cname1Rdata.toByteArray();

        writeU16(out, cname1Bytes.length);
        out.writeBytes(cname1Bytes);

        // Answer 2: b.test CNAME a.test
        writeName(out, "b.test");
        writeU16(out, 5);  // TYPE = CNAME
        writeU16(out, 1);  // CLASS = IN
        writeU32(out, 60); // TTL

        ByteArrayOutputStream cname2Rdata =
                new ByteArrayOutputStream();

        writeName(cname2Rdata, "a.test");

        byte[] cname2Bytes = cname2Rdata.toByteArray();

        writeU16(out, cname2Bytes.length);
        out.writeBytes(cname2Bytes);

        return out.toByteArray();
    }

    private static byte[] truncatedARecord() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Header
        writeU16(out, 0x1234); // ID
        writeU16(out, 0x8400); // QR = 1, AA = 1
        writeU16(out, 1);      // QDCOUNT
        writeU16(out, 1);      // ANCOUNT
        writeU16(out, 0);      // NSCOUNT
        writeU16(out, 0);      // ARCOUNT

        // Question: broken.test A IN
        writeName(out, "broken.test");
        writeU16(out, 1);
        writeU16(out, 1);

        // Answer
        writeName(out, "broken.test");
        writeU16(out, 1);  // TYPE A
        writeU16(out, 1);  // CLASS IN
        writeU32(out, 60); // TTL

        // Claims there should be 4 bytes of RDATA...
        writeU16(out, 4);

        // ...but we deliberately provide only 2.
        out.write(203);
        out.write(0);

        return out.toByteArray();
    }

    private static byte[] wrongIdAnswer() {
        byte[] packet = finalHostAnswer();

        // Change response ID from 0x1234 to 0x5678
        packet[0] = 0x56;
        packet[1] = 0x78;

        return packet;
    }

    private static byte[] wrongOpcodeAnswer() {
        byte[] packet = finalHostAnswer();

        // Original flags = 0x8400
        // Change OPCODE from 0 to 1 while preserving QR and AA.
        packet[2] = (byte) 0x8C;
        packet[3] = 0x00;

        return packet;
    }

    private static byte[] wrongQuestionAnswer() {
        byte[] packet = finalHostAnswer();

        // Question QNAME begins at byte 12:
        //
        // 04 h o s t ...
        //    ^ ^ ^ ^
        //   13 14 15 16
        //
        // Change only the QUESTION from:
        // host.example.com
        //
        // to:
        // evil.example.com

        packet[13] = 'e';
        packet[14] = 'v';
        packet[15] = 'i';
        packet[16] = 'l';

        return packet;
    }

    private static InetAddress rootServer() throws Exception {
        return InetAddress.getByAddress(
                new byte[]{
                        (byte) 198,
                        (byte) 41,
                        (byte) 0,
                        (byte) 4
                }
        );
    }

    private static void testTruncatedRecordRejected() {
        System.out.println("\n=== Truncated record ===");

        try {
            DnsCodec.parseMessage(truncatedARecord());

            System.out.println(
                    "FAIL: truncated record was accepted"
            );

        } catch (IllegalArgumentException e) {
            System.out.println(
                    "PASS: " + e.getMessage()
            );
        }
    }

    private static void testWrongTransactionIdRejected()
            throws Exception {

        System.out.println("\n=== Wrong transaction ID ===");

        InetAddress root = rootServer();

        IterativeResolver.DnsExchange exchange =
                (query, server) -> wrongIdAnswer();

        IterativeResolver resolver =
                new IterativeResolver(root, exchange);

        try {
            resolver.resolveA("host.example.com");

            System.out.println(
                    "FAIL: mismatched transaction ID was accepted"
            );

        } catch (IllegalStateException e) {
            System.out.println(
                    "PASS: " + e.getMessage()
            );
        }
    }

    private static void testWrongQuestionRejected()
            throws Exception {

        System.out.println("\n=== Wrong echoed question ===");

        InetAddress root = rootServer();

        IterativeResolver.DnsExchange exchange =
                (query, server) -> wrongQuestionAnswer();

        IterativeResolver resolver =
                new IterativeResolver(root, exchange);

        try {
            resolver.resolveA("host.example.com");

            System.out.println(
                    "FAIL: wrong echoed question was accepted"
            );

        } catch (IllegalStateException e) {
            System.out.println(
                    "PASS: " + e.getMessage()
            );
        }
    }

    private static void testWrongOpcodeRejected()
            throws Exception {

        System.out.println("\n=== Wrong opcode ===");

        InetAddress root = rootServer();

        IterativeResolver.DnsExchange exchange =
                (query, server) -> wrongOpcodeAnswer();

        IterativeResolver resolver =
                new IterativeResolver(root, exchange);

        try {
            resolver.resolveA("host.example.com");

            System.out.println(
                    "FAIL: unsupported opcode was accepted"
            );

        } catch (IllegalStateException e) {
            System.out.println(
                    "PASS: " + e.getMessage()
            );
        }
    }

    private static void testMissingGlueResolution()
            throws Exception {

        System.out.println("\n=== Missing glue resolution ===");

        InetAddress root = rootServer();

        IterativeResolver.DnsExchange exchange =
                (query, server) -> {

                    String queryName =
                            DnsCodec.decodeName(query, 12).name();

                    if (server.equals(root)
                            && queryName.equalsIgnoreCase(
                            "host.example.com"
                    )) {

                        return referralWithoutGlue();
                    }

                    if (server.equals(root)
                            && queryName.equalsIgnoreCase(
                            "ns1.other.net"
                    )) {

                        return nsAddressAnswer();
                    }

                    if (server.getHostAddress().equals("192.0.2.53")
                            && queryName.equalsIgnoreCase(
                            "host.example.com"
                    )) {

                        return finalHostAnswer();
                    }

                    throw new IOException(
                            "Unexpected scripted query: "
                                    + queryName
                                    + " to "
                                    + server.getHostAddress()
                    );
                };

        IterativeResolver resolver =
                new IterativeResolver(root, exchange);

        List<String> addresses =
                resolver.resolveA("host.example.com");

        if (addresses.size() == 1
                && addresses.get(0).equals("203.0.113.7")) {

            System.out.println(
                    "PASS: resolved to 203.0.113.7"
            );

        } else {
            System.out.println(
                    "FAIL: unexpected result " + addresses
            );
        }
    }

    private static void testRepeatedReferralRejected()
            throws Exception {

        System.out.println("\n=== Repeated referral ===");

        InetAddress root = rootServer();

        IterativeResolver.DnsExchange exchange =
                (query, server) -> {

                    String queryName =
                            DnsCodec.decodeName(query, 12).name();

                    if (server.equals(root)
                            && queryName.equalsIgnoreCase(
                            "host.example.com"
                    )) {

                        return referralWithoutGlue();
                    }

                    if (server.equals(root)
                            && queryName.equalsIgnoreCase(
                            "ns1.other.net"
                    )) {

                        return nsAddressAnswer();
                    }

                    if (server.getHostAddress().equals("192.0.2.53")
                            && queryName.equalsIgnoreCase(
                            "host.example.com"
                    )) {

                        // Deliberately repeat example.com referral.
                        return referralWithoutGlue();
                    }

                    throw new IOException(
                            "Unexpected scripted query: "
                                    + queryName
                                    + " to "
                                    + server.getHostAddress()
                    );
                };

        IterativeResolver resolver =
                new IterativeResolver(root, exchange);

        try {
            resolver.resolveA("host.example.com");

            System.out.println(
                    "FAIL: repeated referral was accepted"
            );

        } catch (IllegalStateException e) {
            System.out.println(
                    "PASS: " + e.getMessage()
            );
        }
    }

    private static void testCnameLoopRejected()
            throws Exception {

        System.out.println("\n=== CNAME loop ===");

        InetAddress root = rootServer();

        IterativeResolver.DnsExchange exchange =
                (query, server) -> {

                    String queryName =
                            DnsCodec.decodeName(query, 12).name();

                    if (server.equals(root)
                            && queryName.equalsIgnoreCase("a.test")) {

                        return cnameLoopAnswer();
                    }

                    throw new IOException(
                            "Unexpected scripted query: "
                                    + queryName
                                    + " to "
                                    + server.getHostAddress()
                    );
                };

        IterativeResolver resolver =
                new IterativeResolver(root, exchange);

        try {
            resolver.resolveA("a.test");

            System.out.println(
                    "FAIL: CNAME loop was accepted"
            );

        } catch (IllegalStateException e) {
            System.out.println(
                    "PASS: " + e.getMessage()
            );
        }
    }
}
