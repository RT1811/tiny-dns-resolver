import java.nio.charset.StandardCharsets;

public class DnsCodec {

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
}
