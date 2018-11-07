import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecureLoggingXmlUtil {

    private final String maskingChar;
    private final String secureFields;
    private final int maskLength;
    private final String regexFieldSplit;

    private List<String> sensitiveFieldsList;
    private String mask;

    public SecureLoggingXmlUtil(String maskingChar, String secureFields, int maskLength, String regexFieldSplit) {
        this.maskingChar = maskingChar;
        this.secureFields = secureFields;
        this.maskLength = maskLength;
        this.regexFieldSplit = regexFieldSplit;
        sensitiveFieldsList = Arrays.asList(secureFields.split(regexFieldSplit));
        mask = buildMask();
    }

    public String maskSensitiveInformation(final String originalLogString) {
        String logWithMasked = originalLogString;
        for (String fieldName : sensitiveFieldsList) {
            logWithMasked = maskFieldsByNameInRawLog(fieldName, mask, logWithMasked);
        }
        return logWithMasked;
    }

    private String maskFieldsByNameInRawLog(String fieldName, String mask, String rawLog) {
        String regexp = String.format("(?<beforeTagValue><%1$s>)(.*)(?<afterTagValue></%1$s>)", fieldName);
        Matcher xmlNodeMatcher = Pattern.compile(regexp).matcher(rawLog);
        if (xmlNodeMatcher.find()) {
            return xmlNodeMatcher.replaceAll(String.format("${beforeTagValue}%s${afterTagValue}", mask));
        }
        return rawLog;
    }

    private String buildMask() {
        char[] mask = new char[maskLength];
        Arrays.fill(mask, maskingChar.charAt(0));
        return new String(mask);
    }
}
