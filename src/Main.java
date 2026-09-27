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

        DnsMessage message = DnsCodec.parseMessage(response);

        System.out.println("ID: " + message.id());
        System.out.println("Flags: " + message.flags());
        System.out.println("Answers: " + message.answers().size());
        System.out.println("Authorities: " + message.authorities().size());
        System.out.println("Additionals: " + message.additionals().size());

        DnsCodec.ResourceRecord rr = message.authorities().get(0);

        System.out.println(rr.name() + " type=" + rr.type());
    }
}