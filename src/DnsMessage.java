import java.util.List;

public class DnsMessage {
    private final int id;
    private final int flags;
    private final int qdCount;
    private final int anCount;
    private final int nsCount;
    private final int arCount;

    private final List<DnsCodec.ResourceRecord> answers;
    private final List<DnsCodec.ResourceRecord> authorities;
    private final List<DnsCodec.ResourceRecord> additionals;

    public DnsMessage(
            int id,
            int flags,
            int qdCount,
            int anCount,
            int nsCount,
            int arCount,
            List<DnsCodec.ResourceRecord> answers,
            List<DnsCodec.ResourceRecord> authorities,
            List<DnsCodec.ResourceRecord> additionals
    ) {
        this.id = id;
        this.flags = flags;
        this.qdCount = qdCount;
        this.anCount = anCount;
        this.nsCount = nsCount;
        this.arCount = arCount;
        this.answers = answers;
        this.authorities = authorities;
        this.additionals = additionals;
    }

    public int id() {
        return id;
    }

    public int flags() {
        return flags;
    }

    public int qdCount() {
        return qdCount;
    }

    public int anCount() {
        return anCount;
    }

    public int nsCount() {
        return nsCount;
    }

    public int arCount() {
        return arCount;
    }

    public List<DnsCodec.ResourceRecord> answers() {
        return answers;
    }

    public List<DnsCodec.ResourceRecord> authorities() {
        return authorities;
    }

    public List<DnsCodec.ResourceRecord> additionals() {
        return additionals;
    }

    public boolean isResponse() {
        return (flags & 0x8000) != 0;
    }

    public boolean isTruncated() {
        return (flags & 0x0200) != 0;
    }

    public int rcode() {
        return flags & 0x000F;
    }

    public boolean isAuthoritative() {
        return (flags & 0x0400) != 0;
    }
}
