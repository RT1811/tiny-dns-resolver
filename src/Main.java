public class Main {
    public static void main(String[] args) {
        byte[] query = DnsCodec.encodeAQuery("example.com", 0x1234);
        System.out.println(query.length);
        for (byte b : query) {
            System.out.printf("%02X ", b & 0xFF);
        }
        System.out.println();
    }
}