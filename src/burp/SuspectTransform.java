package burp;

import java.util.*;
import java.util.Random;

import static burp.PerHostScans.htmlEncode;
import static burp.PerHostScans.safeBytesToString;
import static burp.Utilities.helpers;

public class SuspectTransform extends ParamScan {
    // U+DC2A as a lone surrogate, in the naive 3-byte UTF-8 form (WTF-8). This cannot be
    // expressed as a Java String: no unpaired surrogate has a valid UTF-8 encoding, so
    // String.getBytes() would silently replace it with '?' before the request is sent.
    private static final byte[] LONE_SURROGATE = {(byte) 0xED, (byte) 0xB0, (byte) 0xAA};

    private Map<String, CheckDetails> checks;
    private int confirmCount;

    public SuspectTransform(String name) {
        super(name);
        this.checks = new HashMap<>();
        this.checks.put("quote consumption", new CheckDetails(this::detectQuoteConsumption, List.of()));
        this.checks.put("arithmetic evaluation", new CheckDetails(this::detectArithmetic, List.of()));
        this.checks.put("expression evaluation", new CheckDetails(this::detectExpression,
                List.of("https://portswigger.net/research/server-side-template-injection")));
        this.checks.put("template evaluation", new CheckDetails(this::detectRazorExpression,
                List.of("https://portswigger.net/research/server-side-template-injection")));
        this.checks.put("EL evaluation", new CheckDetails(this::detectAltExpression,
                List.of("https://portswigger.net/research/server-side-template-injection")));
        this.checks.put("unicode normalisation", new CheckDetails(this::detectUnicodeNormalisation,
                List.of("https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/")));
        this.checks.put("url decoding error", new CheckDetails(this::detectUrlDecodeError,
                List.of("https://cwe.mitre.org/data/definitions/172.html")));
        this.checks.put("unicode byte truncation", new CheckDetails(this::detectUnicodeByteTruncation,
                List.of("https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows")));
        this.checks.put("unicode case conversion", new CheckDetails(this::detectUnicodeCaseConversion,
                List.of("https://www.unicode.org/charts/case/index.html")));
        this.checks.put("unicode combining diacritic", new CheckDetails(this::detectUnicodeCombiningDiacritic,
                List.of("https://codepoints.net/combining_diacritical_marks?lang=en")));
        this.checks.put("legacy url decoding (single-byte)", new CheckDetails(this::detectLegacyUrlDecode,
                List.of("https://datatracker.ietf.org/doc/html/rfc1738#section-2.2")));
        this.checks.put("surrogate character replacement", new CheckDetails(this::detectSurrogateReplacement,
                List.of("https://lab.ctbb.show/research/unicode-surrogates-to-replacement-characters")));
        this.checks.put("unicode bitwise overflow", new CheckDetails(this::detectUnicodeBitwiseOverflow,
                List.of("https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows")));
        this.checks.put("unicode space conversion", new CheckDetails(this::detectUnicodeSpaceConvert,
                List.of("https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes")));
        this.confirmCount = 2;
    }

    private Probe detectUnicodeSpaceConvert(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);

        // Probe sends the EN QUAD character (\u2000) between the anchors
        String probe = leftAnchor + "\u2000" + rightAnchor;

        // We check for two possibilities:
        // 1. The character is converted to a standard space (" ")
        // 2. The character is completely stripped/trimmed out ("")
        return Probe.of(probe, leftAnchor + " " + rightAnchor, leftAnchor + rightAnchor);
    }

    private Probe detectUnicodeBitwiseOverflow(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);

        // 0x8336 (茶) masks down to 0x36 ('6') when evaluated with an '& 255' bitwise overflow
        String probe = leftAnchor + "\u8336" + rightAnchor;

        // Expect the backend parser to evaluate the bitwise operation and output a literal '6'
        return Probe.of(probe, leftAnchor + "6" + rightAnchor);
    }

    private Probe detectSurrogateReplacement(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);

        // The lone surrogate has to go on the wire as raw bytes - see LONE_SURROGATE. Burp
        // applies whatever encoding the insertion point needs (eg %ED%B0%AA for a URL param).
        byte[] probe = concat(leftAnchor.getBytes(), LONE_SURROGATE, rightAnchor.getBytes());

        // Some parsers simplify the U+FFFD replacement character all the way down to '?'
        return Probe.ofBytes(probe, leftAnchor + "?" + rightAnchor);
    }

    private Probe detectLegacyUrlDecode(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);

        // The probe sends the literal string "%ff" between the anchors
        String probe = leftAnchor + "%ff" + rightAnchor;

        // The expected response checks for the decoded 'ÿ' (\u00FF) character between the anchors
        return Probe.of(probe, leftAnchor + "\u00FF" + rightAnchor);
    }

    private Probe detectUnicodeNormalisation(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return Probe.of(leftAnchor + "\u212a" + rightAnchor, leftAnchor + "K" + rightAnchor);
    }

    private Probe detectUrlDecodeError(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return Probe.of(leftAnchor + "\u0391" + rightAnchor, leftAnchor + "N\u0011" + rightAnchor);
    }

    private Probe detectUnicodeByteTruncation(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return Probe.of(leftAnchor + "\uCF7B" + rightAnchor, leftAnchor + "{" + rightAnchor);
    }

    private Probe detectUnicodeCaseConversion(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return Probe.of(leftAnchor + "\u0131" + rightAnchor, leftAnchor + "I" + rightAnchor);
    }

    private Probe detectUnicodeCombiningDiacritic(String base) {
        String rightAnchor = Utilities.randomString(6);
        return Probe.of("\u0338" + rightAnchor, "\u226F" + rightAnchor);
    }

    private Probe detectQuoteConsumption(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return Probe.of(leftAnchor + "''" + rightAnchor, leftAnchor + "'" + rightAnchor);
    }

    private Probe detectArithmetic(String base) {
        Random random = new Random();
        int x = 99 + random.nextInt(9901);
        int y = 99 + random.nextInt(9901);
        return Probe.of(x + "*" + y, String.valueOf(x * y));
    }

    private Probe detectExpression(String base) {
        Probe arithmetic = detectArithmetic(base);
        return arithmetic.wrap("${", "}");
    }

    private Probe detectAltExpression(String base) {
        Probe arithmetic = detectArithmetic(base);
        return arithmetic.wrap("%{", "}");
    }

    private Probe detectRazorExpression(String base) {
        Probe arithmetic = detectArithmetic(base);
        return arithmetic.wrap("@(", ")");
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        String base = insertionPoint.getBaseValue();
        String initialResponse = safeBytesToString(basePair.getResponse());
        List<IScanIssue> issues = new ArrayList<>();
        Map<String, CheckDetails> checksCopy = new HashMap<>(this.checks);

        while (!checksCopy.isEmpty()) {
            Map.Entry<String, CheckDetails> entry = checksCopy.entrySet().iterator().next();
            checksCopy.remove(entry.getKey());
            String name = entry.getKey();
            Check check = entry.getValue().getTransformation();
            List<String> links = entry.getValue().getLinks();

            for (int attempt = 0; attempt < confirmCount; attempt++) {
                Probe result = check.apply(base);
                byte[] probe = result.payload();
                List<String> expect = result.expected();

                // Decoded the same way we decode responses. If the probe already reads as the
                // transformed value then any 'match' is our own encoding, not the server's.
                String wireProbe = safeBytesToString(probe);

                Utilities.log("Trying " + wireProbe);
                IHttpRequestResponse attack = OldUtilities.request2(basePair, insertionPoint, probe);
                String attackResponse = safeBytesToString(attack.getResponse());

                boolean matched = false;
                for (String e : expect) {
                    if (attackResponse.contains(e) && !initialResponse.contains(e) && !wireProbe.contains(e)) {
                        matched = true;
                        if (attempt == confirmCount - 1) {
                            issues.add(new CustomScanIssue(
                                    attack.getHttpService(),
                                    helpers.analyzeRequest(attack).getUrl(),
                                    new IHttpRequestResponse[]{attack},
                                    "Suspicious input transformation: " + name,
                                    "The application transforms input in a manner that indicates potential vulnerability (e.g., code injection, validation bypass, etc.):<br/><br/> "
                                            + "The following probe was sent: <b>" + htmlEncode(describe(probe)) + "</b><br/>"
                                            + "The server response contained the evaluated result: <b>" + htmlEncode(e) + "</b><br/><br/>Manual investigation is advised."
                                            + (links.isEmpty() ? "" : "<br/> More details: " + String.join(", ", links)),
                                    "Tentative", CustomScanIssue.severity.High));
                        }
                        break;
                    }
                }

                if (!matched) {
                    break;
                }
            }
        }

        return issues;
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }

    // Probes may contain bytes that aren't printable (or aren't valid UTF-8), so render
    // anything outside printable ASCII as a hex escape rather than dropping it into the report.
    // HTML-significant characters are left alone here; htmlEncode handles them at the call site.
    private static String describe(byte[] probe) {
        StringBuilder out = new StringBuilder();
        for (byte b : probe) {
            int c = b & 0xFF;
            if (c >= 0x20 && c <= 0x7E) {
                out.append((char) c);
            } else {
                out.append(String.format("\\x%02x", c));
            }
        }
        return out.toString();
    }

    private record Probe(byte[] payload, List<String> expected) {
        static Probe of(String payload, String... expected) {
            return new Probe(payload.getBytes(), List.of(expected));
        }

        static Probe ofBytes(byte[] payload, String... expected) {
            return new Probe(payload, List.of(expected));
        }

        // Surround the payload, keeping the expected results untouched - used by the template
        // engine checks, which look for the result of an arithmetic probe they've wrapped.
        Probe wrap(String prefix, String suffix) {
            return new Probe(concat(prefix.getBytes(), payload, suffix.getBytes()), expected);
        }
    }

    private static class CheckDetails {
        private final Check transformation;
        private final List<String> links;

        public CheckDetails(Check transformation, List<String> usefulLinks) {
            this.transformation = transformation;
            this.links = usefulLinks;
        }

        public Check getTransformation() {
            return transformation;
        }

        public List<String> getLinks() {
            return links.stream()
                    .map(link -> String.format("<a href=\"%s\">%s</a>", link, link)).toList();
        }
    }

    @FunctionalInterface
    private interface Check {
        Probe apply(String base);
    }

    // Other utility methods like safeBytesToString, request, debugMsg, etc. should be implemented as needed.
}
