import java.nio.charset.StandardCharsets;

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

    public static DecodedName decodeName(byte[] packet, int offset) {
        if (offset < 0 || offset >= packet.length) {
            throw new IllegalArgumentException("DNS name offset outside packet");
        }

        StringBuilder name = new StringBuilder();

        while(true) {
            if (offset >= packet.length) {
                throw new IllegalArgumentException("DNS name has no terminator");
            }

            int length = packet[offset] & 0xFF;


            if (length == 0) {
                offset++;
                break;
            }
            if ((length & 0xC0) == 0xC0) {
                throw new IllegalArgumentException(
                        "Compressed DNS names not supported yet"
                );
            }

            if (length > 63) {
                throw new IllegalArgumentException("Invalid DNS label length");
            }


            offset++;

            if (offset + length > packet.length) {
                throw new IllegalArgumentException(
                        "DNS label extends beyond packet"
                );
            }

            String label = new String(
                    packet,
                    offset,
                    length,
                    StandardCharsets.US_ASCII
            );

            if (name.length() > 0) {
                name.append('.');
            }

            name.append(label);

            offset += length;
        }

        return new DecodedName(name.toString(), offset);
    }
}
