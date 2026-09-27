import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DnsCodec {

    public static class DecodedName {
        private final String name;
        private final int nextOffset;

        public DecodedName(String name, int nextOffset) {
            this.name = name;
            this.nextOffset = nextOffset;
        }

        public String name() {
            return name;
        }

        public int nextOffset() {
            return nextOffset;
        }
    }

    public static class ResourceRecord {
        private final String name;
        private final int type;
        private final int recordClass;
        private final long ttl;
        private final int rdLength;
        private final int rdataOffset;
        private final int nextOffset;

        public ResourceRecord (
                String name,
                int type,
                int recordClass,
                long ttl,
                int rdLength,
                int rdataOffset,
                int nextOffset
        ) {
            this.name = name;
            this.type = type;
            this.recordClass = recordClass;
            this.ttl = ttl;
            this.rdLength = rdLength;
            this.rdataOffset = rdataOffset;
            this.nextOffset = nextOffset;
        }

        public String name() {
            return name;
        }

        public int type() {
            return type;
        }

        public int recordClass() {
            return recordClass;
        }

        public long ttl() {
            return ttl;
        }

        public int rdLength() {
            return rdLength;
        }

        public int rdataOffset() {
            return rdataOffset;
        }

        public int nextOffset() {
            return nextOffset;
        }
    }

    public static byte[] encodeAQuery(String hostname, int transactionId) {
        int queryLength = 12 + encodedNameLength(hostname) + 4;

        byte[] query = new byte[queryLength];
        int offset = 0;

        offset = writeU16(query, offset, transactionId);
        offset = writeU16(query, offset, 0); // flags
        offset = writeU16(query, offset, 1); // QDCOUNT
        offset = writeU16(query, offset, 0); // ANCOUNT
        offset = writeU16(query, offset, 0); // NSCOUNT
        offset = writeU16(query, offset, 0); // ARCOUNT

        String[] labels = hostname.split("\\.");
        for (String label: labels) {
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);

            query[offset++] = (byte) labelBytes.length;

            for (byte b : labelBytes) {
                query[offset++] = b;
            }
        }

        query[offset++] = 0;

        offset = writeU16(query, offset, 1); // QTYPE = A
        offset = writeU16(query, offset, 1); // QCLASS = IN

        return query;
    }

    private static int writeU16(byte[] buffer, int offset, int value) {
        buffer[offset++] = (byte) ((value >> 8) & 0xFF);
        buffer[offset++] = (byte) (value & 0xFF);
        return offset;
    }

    private static int encodedNameLength(String hostname) {
        String[] labels = hostname.split("\\.");
        int length = 0;

        for (String label : labels) {
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);

            length++;
            length += labelBytes.length;
        }

        length++;

        return length;
    }

    public static int readU16(byte[] packet, int offset) {
        if (offset < 0 || offset + 1 >= packet.length) {
            throw new IllegalArgumentException("Not enough bytes to read a 16-bit value");
        }

        int high = packet[offset] & 0xFF;
        int low = packet[offset + 1] & 0xFF;

        return (high << 8) | low;
    }

    public static long readU32(byte[] packet, int offset) {
        long b1 = packet[offset] & 0xFFL;
        long b2 = packet[offset + 1] & 0xFFL;
        long b3 = packet[offset + 2] & 0xFFL;
        long b4 = packet[offset + 3] & 0xFFL;

        return (b1 << 24)
                | (b2 << 16)
                | (b3 << 8)
                | b4;
    }

    public static DecodedName decodeName(byte[] packet, int offset) {
        if (offset < 0 || offset >= packet.length) {
            throw new IllegalArgumentException("DNS name offset outside packet");
        }

        int cursor = offset;
        int nextOffset = -1;
        boolean[] visited = new boolean[packet.length];
        StringBuilder name = new StringBuilder();

        while (true) {
            if (cursor >= packet.length) {
                throw new IllegalArgumentException("DNS name has no terminator");
            }

            int length = packet[cursor] & 0xFF;

            if ((length & 0xC0) == 0xC0) {
                if (cursor + 1 >= packet.length) {
                    throw new IllegalArgumentException(
                            "Truncated DNS compression pointer"
                    );
                }

                int secondByte = packet[cursor + 1] & 0xFF;

                int pointerOffset =
                        ((length & 0x3F) << 8) | secondByte;

                if (pointerOffset >= packet.length) {
                    throw new IllegalArgumentException(
                            "DNS compression pointer outside packet"
                    );
                }

                if (visited[pointerOffset]) {
                    throw new IllegalArgumentException("DNS compression pointer loop");
                }

                visited[pointerOffset] = true;

                if (nextOffset == -1) {
                    nextOffset = cursor + 2;
                }

                cursor = pointerOffset;
                continue;
            }

            if (length == 0) {
                cursor++;

                if (nextOffset == -1) {
                    nextOffset = cursor;
                }

                break;
            }

            if (length > 63) {
                throw new IllegalArgumentException("Invalid DNS label length");
            }

            cursor++;

            if (cursor + length > packet.length) {
                throw new IllegalArgumentException(
                        "DNS label extends beyond packet"
                );
            }

            String label = new String(
                    packet,
                    cursor,
                    length,
                    StandardCharsets.US_ASCII
            );

            if (name.length() > 0) {
                name.append('.');
            }

            name.append(label);

            cursor += length;
        }

        return new DecodedName(name.toString(), nextOffset);
    }

    public static ResourceRecord parseResourceRecord(byte[] packet, int offset) {
        DecodedName owner = decodeName(packet, offset);
        offset = owner.nextOffset();

        int type = readU16(packet, offset);
        offset += 2;

        int recordClass = readU16(packet, offset);
        offset += 2;

        long ttl = readU32(packet, offset);
        offset += 4;

        int rdLength = readU16(packet, offset);
        offset += 2;

        int rdataStart = offset;
        int nextRecordOffset = rdataStart + rdLength;

        if (nextRecordOffset > packet.length) {
            throw new IllegalArgumentException(
                    "DNS RDATA extends beyond packet"
            );
        }

        return new ResourceRecord(
                owner.name(),
                type,
                recordClass,
                ttl,
                rdLength,
                rdataStart,
                nextRecordOffset
        );
    }

    public static String decodeARecord(byte[] packet, ResourceRecord rr) {
        if (rr.type() != 1) {
            throw new IllegalArgumentException("Not an A record");
        }

        if (rr.rdLength() != 4) {
            throw new IllegalArgumentException("Invalid A record length");
        }

        int offset = rr.rdataOffset();
        int a = packet[offset] & 0xFF;
        int b = packet[offset + 1] & 0xFF;
        int c = packet[offset + 2] & 0xFF;
        int d = packet[offset + 3] & 0xFF;

        return a + "." + b + "." + c + "." + d;
    }

    public static DnsMessage parseMessage(byte[] packet) {
        List<ResourceRecord> answers = new ArrayList<>();
        List<ResourceRecord> authorities = new ArrayList<>();
        List<ResourceRecord> additionals = new ArrayList<>();

        int id = readU16(packet, 0);
        int flags = readU16(packet, 2);
        int qdCount = readU16(packet, 4);
        int anCount = readU16(packet, 6);
        int nsCount = readU16(packet, 8);
        int arCount = readU16(packet, 10);

        DnsCodec.DecodedName decoded = DnsCodec.decodeName(packet, 12);

        int offset = 12;

        for (int i = 0; i < qdCount; i++) {
            DecodedName question = decodeName(packet, offset);
            offset = question.nextOffset();

            if (offset + 4 > packet.length) {
                throw new IllegalArgumentException(
                        "DNS question extends beyond packet"
                );
            }

            offset += 4; // QTYPE + QCLASS
        }

        for (int i = 0; i < anCount; i++) {
            ResourceRecord rr = parseResourceRecord(packet, offset);
            answers.add(rr);
            offset = rr.nextOffset();
        }

        for (int i = 0; i < nsCount; i++) {
            ResourceRecord rr = parseResourceRecord(packet, offset);
            authorities.add(rr);
            offset = rr.nextOffset();
        }

        for (int i = 0; i < arCount; i++) {
            ResourceRecord rr = parseResourceRecord(packet, offset);
            additionals.add(rr);
            offset = rr.nextOffset();
        }

        return new DnsMessage(
                id,
                flags,
                qdCount,
                anCount,
                nsCount,
                arCount,
                answers,
                authorities,
                additionals
        );
    }
}
