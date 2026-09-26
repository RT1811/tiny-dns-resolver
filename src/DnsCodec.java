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
}
