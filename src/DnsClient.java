import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

public class DnsClient {

    public static byte[] exchange(byte[] query, InetAddress server) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {

            socket.setSoTimeout(2000);

            DatagramPacket packet =
                    new DatagramPacket(query, query.length, server, 53);

            socket.send(packet);

            byte[]  buffer = new byte[512];

            DatagramPacket responsePacket =
                    new DatagramPacket(buffer, buffer.length);

            socket.receive(responsePacket);

            int responseLength = responsePacket.getLength();

            return Arrays.copyOf(buffer, responseLength);
        }
    }
}
