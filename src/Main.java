import java.io.IOException;
import java.net.InetAddress;

public class Main {
    public static void main(String[] args) throws IOException {
        byte[] query = DnsCodec.encodeAQuery(
                "example.com",
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

        for (int i = 0; i < 12; i++) {
            System.out.printf("%02X ", response[i] & 0xFF);
        }
        System.out.println();

        int id = DnsCodec.readU16(response,0);
        int flags   = DnsCodec.readU16(response, 2);
        int qdCount = DnsCodec.readU16(response, 4);
        int anCount = DnsCodec.readU16(response, 6);
        int nsCount = DnsCodec.readU16(response, 8);
        int arCount = DnsCodec.readU16(response, 10);

        System.out.println("ID = " + id);
        System.out.println("Flags = " + flags);
        System.out.println("qdCount = " + qdCount);
        System.out.println("anCount = " + anCount);
        System.out.println("nsCount = " + nsCount);
        System.out.println("arCount = " + arCount);

        boolean isResponse = (flags & 0x8000) != 0;
        boolean truncated = (flags & 0x0200) != 0;
        int rcode = flags & 0x000F;

        System.out.println("Is response: " + isResponse);
        System.out.println("Truncated: " + truncated);
        System.out.println("RCODE: " + rcode);

        DnsCodec.DecodedName decoded = DnsCodec.decodeName(response, 12);

        System.out.println(decoded.name());
        System.out.println(decoded.nextOffset());
    }
}