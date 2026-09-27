import java.io.IOException;
import java.net.InetAddress;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {

        InetAddress rootServer = InetAddress.getByAddress(
                new byte[]{
                        (byte) 198,
                        (byte) 41,
                        (byte) 0,
                        (byte) 4
                }
        );

        IterativeResolver resolver = new IterativeResolver(rootServer);

        List<String> addresses = resolver.resolveA("ubc.ca");

        System.out.println("Resolved addresses:");

        for (String address : addresses) {
            System.out.println(address);
        }
    }
}