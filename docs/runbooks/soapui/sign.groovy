// Step 1 of the getSystemStatus manual check (CTO only; design §13 #36, runbook 01 "SoapUI calls").
// Run it only with the TestCase window's Run button. It never logs a SITEST value or the signature.
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.swing.JOptionPane
import javax.swing.JPasswordField
import javax.swing.SwingUtilities
import javax.swing.event.AncestorEvent
import javax.swing.event.AncestorListener

// The code names a check or a field, never a value. It goes to the script log and stops the run.
void stop(String code) {
    log.info("STOP " + code)
    throw new IllegalStateException("STOP " + code)
}

void zero(char[] value) {
    if (value != null) {
        Arrays.fill(value, (char) 0)
    }
}

SimpleDateFormat utcFormat() {
    SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT)
    format.setTimeZone(TimeZone.getTimeZone("UTC"))
    return format
}

// Base64(HMAC-SHA1(key = secret, data)), as gateway/signing.py does.
String hmacSha1Base64(char[] secret, String data) {
    ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(secret))
    byte[] key = new byte[encoded.remaining()]
    encoded.get(key)
    if (encoded.hasArray()) {
        Arrays.fill(encoded.array(), (byte) 0)
    }
    try {
        Mac mac = Mac.getInstance("HmacSHA1")
        mac.init(new SecretKeySpec(key, "HmacSHA1"))
        return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)))
    } finally {
        Arrays.fill(key, (byte) 0)
    }
}

// After each field, so a stray paste in the next one is empty instead of the last value.
void clearClipboard() {
    try {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(""), null)
    } catch (Exception ignored) {
        // No clipboard (headless): nothing to clear.
    }
}

// A hidden field: paste from Keeper; it shows one dot per character, never the value.
char[] askHidden(String label) {
    JPasswordField field = new JPasswordField(40)
    // Without this, focus starts on OK and a paste goes nowhere.
    field.addAncestorListener(new AncestorListener() {
        void ancestorAdded(AncestorEvent event) {
            SwingUtilities.invokeLater({ event.getComponent().requestFocusInWindow() } as Runnable)
        }
        void ancestorRemoved(AncestorEvent event) {}
        void ancestorMoved(AncestorEvent event) {}
    })
    int[] answer = new int[1]
    def parent = null
    try {
        // SoapUI's main window, so the field opens in front of it.
        parent = Class.forName("com.eviware.soapui.support.UISupport").getMethod("getMainFrame").invoke(null)
    } catch (Exception ignored) {
        parent = null
    }
    Runnable show = {
        answer[0] = JOptionPane.showConfirmDialog(
            parent, field, label, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
    } as Runnable
    if (SwingUtilities.isEventDispatchThread()) {
        show.run()
    } else {
        SwingUtilities.invokeAndWait(show)
    }
    char[] value = field.getPassword()
    field.setText("")
    clearClipboard()
    if (answer[0] != JOptionPane.OK_OPTION) {
        zero(value)
        stop("CANCELLED")
    }
    return value
}

// As recorder init does: empty, edge spaces and control characters are refused.
void checkValue(String name, char[] value, boolean xmlText) {
    if (value.length == 0) {
        stop("EMPTY " + name)
    }
    if (Character.isWhitespace(value[0]) || Character.isWhitespace(value[value.length - 1])) {
        stop("SPACE " + name)
    }
    for (int i = 0; i < value.length; i++) {
        char ch = value[i]
        if (Character.isISOControl(ch)) {
            stop("INVALID " + name)
        }
        if (xmlText && (ch == ('<' as char) || ch == ('>' as char) || ch == ('&' as char))) {
            stop("INVALID " + name)
        }
    }
}

// The recorder's request (gateway/envelope.py): the six fields in the WSDL's order,
// callerPassword present and empty. Placeholders only; the values stay in test case properties.
String envelope(String caller, boolean withSp) {
    List<String> lines = [
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:irid="http://www.iridium.com">',
        '  <soap:Body>',
        '    <irid:getSystemStatus>',
        '      <request>',
        '        <iwsUsername>${#TestCase#iwsUsername}</iwsUsername>',
        '        <signature>${#TestCase#signature}</signature>',
    ]
    if (withSp) {
        lines.add('        <serviceProviderAccountNumber>${#TestCase#spAccount}</serviceProviderAccountNumber>')
    }
    lines.addAll([
        '        <timestamp>${#TestCase#timestamp}</timestamp>',
        '        <caller>' + caller + '</caller>',
        '        <callerPassword></callerPassword>',
        '      </request>',
        '    </irid:getSystemStatus>',
        '  </soap:Body>',
        '</soap:Envelope>',
    ])
    return lines.join("\n")
}

String OPERATION = "getSystemStatus"
String ENDPOINT = "https://iwstraining.iridium.com:8443/iws-current/iws"
// The recorder's caller (rec.RP-2026-001) with "cto." instead of "rec." (runbook 01 rule 4).
String CALLER = "cto.RP-2026-001"
String TIMEOUT_MS = "120000"
String NOT_SIGNED = "NOT SIGNED: the sign step did not finish. Do not send."
String SENT_FLAG = "airtimesat.manualCheck.sent"

// 1. Only the TestCase window's Run button. The script editor's Run arrow (or Option+Return)
// uses a mock runner: it would sign, never send, and skip the teardown.
if (testRunner.getClass().getSimpleName() != "WsdlTestCaseRunner") {
    stop("RUNNER")
}
def testCase = testRunner.testCase
testCase.setFailOnError(true)
def steps = testCase.getTestStepList()
if (steps.size() == 2 && steps.get(1).getClass().getSimpleName() == "WsdlTestRequestStep") {
    steps.get(1).getTestRequest().setRequestContent(NOT_SIGNED)
}
if (testCase.getPropertyValue("oneCallDone") == "yes" || System.getProperty(SENT_FLAG) == "yes") {
    stop("ALREADY_SENT")
}
String tearDown = (testCase.getTearDownScript() ?: "").trim()
boolean tearDownOk = tearDown.startsWith("// Teardown of the getSystemStatus manual check") && tearDown.endsWith("log.info(result)")
if (tearDownOk) {
    try {
        new GroovyShell(this.class.classLoader).parse(tearDown)
    } catch (Exception ignored) {
        tearDownOk = false
    }
}
if (!tearDownOk) {
    stop("TEARDOWN")
}

// 2. Offline self-tests with the synthetic vector of tests/gateway/test_signing.py.
SimpleDateFormat format = utcFormat()
if (format.format(new Date(1798761599000L)) != "2026-12-31T23:59:59Z") {
    stop("SELF_TEST_TIMESTAMP")
}
if (hmacSha1Base64("fake-secret-not-real-0002".toCharArray(), "getSystemStatus2026-12-31T23:59:59Z")
        != "L6PjH7z4A8ePJXfsbc78xBHWqL8=") {
    stop("SELF_TEST_SIGNATURE")
}
log.info("OK self-tests: UTC timestamp, HMAC-SHA1 Base64")

// 3. The test case: this script, then one SOAP request for getSystemStatus at SITEST.
if (steps.size() != 2 || steps.get(0).getClass().getSimpleName() != "WsdlGroovyScriptTestStep"
        || steps.get(1).getClass().getSimpleName() != "WsdlTestRequestStep") {
    stop("STEPS")
}
def request = steps.get(1).getTestRequest()
if (request.getOperation().getName() != OPERATION) {
    stop("OPERATION")
}
if (request.getEndpoint() != ENDPOINT) {
    stop("ENDPOINT")
}
request.setFollowRedirects(false)
request.setRemoveEmptyContent(false)
request.setTimeout(TIMEOUT_MS)
if (request.isFollowRedirects() || request.isRemoveEmptyContent() || request.getTimeout() != TIMEOUT_MS) {
    stop("REQUEST_SETTINGS")
}
// SoapUI's proxy must be off, so that the /etc/hosts pin decides the address.
boolean proxyOn = true
try {
    proxyOn = Class.forName("com.eviware.soapui.impl.wsdl.support.http.ProxyUtils").getMethod("isProxyEnabled").invoke(null)
} catch (Exception ignored) {
    proxyOn = true
}
if (proxyOn) {
    stop("PROXY")
}
log.info("OK test case: teardown, endpoint, operation, redirects off, proxy off, empty content kept")

// 4. The SITEST values, from Keeper, in R init's order. Signed last, so the timestamp is fresh.
char[] username = null
char[] secret = null
char[] sp = null
try {
    username = askHidden("SITEST username (paste from Keeper)")
    checkValue("username", username, true)
    secret = askHidden("SITEST secret key (paste from Keeper)")
    checkValue("secret key", secret, false)
    if (Arrays.equals(username, secret)) {
        stop("SAME_VALUE username, secret key")
    }
    sp = askHidden("SP account number (as at R init; leave empty and press OK if none)")
    if (sp.length > 0) {
        checkValue("SP account number", sp, true)
        if (Arrays.equals(sp, secret) || Arrays.equals(sp, username)) {
            stop("SAME_VALUE SP account number")
        }
    }
    String timestamp = format.format(new Date())
    String signature = hmacSha1Base64(secret, OPERATION + timestamp)
    testCase.setPropertyValue("iwsUsername", new String(username))
    testCase.setPropertyValue("spAccount", sp.length > 0 ? new String(sp) : "")
    testCase.setPropertyValue("timestamp", timestamp)
    testCase.setPropertyValue("signature", signature)
    testCase.setPropertyValue("oneCallDone", "yes")
    System.setProperty(SENT_FLAG, "yes")
    context.setProperty("signedThisRun", "yes")
    context.setProperty("spSent", sp.length > 0 ? "with" : "without")
    request.setRequestContent(envelope(CALLER, sp.length > 0))
    log.info("OK signed " + OPERATION + " at " + timestamp + " UTC" + (sp.length > 0 ? ", with" : ", without")
        + " serviceProviderAccountNumber, callerPassword empty; sending now")
} finally {
    zero(username)
    zero(secret)
    zero(sp)
}
