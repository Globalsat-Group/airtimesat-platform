// Teardown of the getSystemStatus manual check (CTO only). Clears the values, then prints the
// outcome as codes and WSDL field names only, never the response text (gateway/faults.py rule).
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Node
import org.xml.sax.ErrorHandler
import org.xml.sax.InputSource

String SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
List<String> AUTH_FIELDS = ["iwsUsername", "signature", "serviceProviderAccountNumber", "timestamp", "caller", "callerPassword"]
List<String> ERROR_CODES = ["AUTH", "CONFIG", "FIELD", "SYS"]

String classify(def response, String soap12, List<String> authFields, List<String> errorCodes) {
    if (response == null) {
        return "no_response: no HTTP response (connection, TLS or timeout error, or Cancel)"
    }
    int status = response.getStatusCode()
    if (status >= 300 && status < 400) {
        return "http=" + status + " redirect_not_followed"
    }
    String body = response.getContentAsString()
    def factory = DocumentBuilderFactory.newInstance()
    factory.setNamespaceAware(true)
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    factory.setExpandEntityReferences(false)
    def builder = factory.newDocumentBuilder()
    builder.setErrorHandler([
        warning: { e -> },
        error: { e -> throw e },
        fatalError: { e -> throw e },
    ] as ErrorHandler)
    def document
    try {
        document = builder.parse(new InputSource(new StringReader(body == null ? "" : body)))
    } catch (Exception ignored) {
        return "http=" + status + " outcome=unknown not_xml"
    }
    def root = document.getDocumentElement()
    if (root.getNamespaceURI() != soap12 || root.getLocalName() != "Envelope") {
        return "http=" + status + " outcome=unknown not_soap12"
    }
    def faults = document.getElementsByTagNameNS(soap12, "Fault")
    if (faults.getLength() == 0) {
        def answers = document.getElementsByTagNameNS("*", "getSystemStatusResponse")
        return "http=" + status + " outcome=" + (answers.getLength() == 1 ? "ok" : "unknown no_fault_no_answer")
    }
    def fault = faults.item(0)
    String soapCode = "-"
    def values = fault.getElementsByTagNameNS(soap12, "Value")
    if (values.getLength() > 0) {
        String text = values.item(0).getTextContent().trim()
        String local = text.substring(text.lastIndexOf(":") + 1)
        soapCode = local in ["Sender", "Receiver", "VersionMismatch", "MustUnderstand"] ? local : "unknown"
    }
    String errorCode = "unknown"
    def all = fault.getElementsByTagNameNS("*", "*")
    for (int i = 0; i < all.getLength(); i++) {
        def element = all.item(i)
        String text = element.getTextContent().trim()
        if (element.getLocalName().toLowerCase().contains("code") && text in errorCodes) {
            errorCode = text
            break
        }
    }
    // Each text node on its own, so names in adjacent elements do not run together.
    List<String> parts = []
    for (int i = 0; i < all.getLength(); i++) {
        def children = all.item(i).getChildNodes()
        for (int j = 0; j < children.getLength(); j++) {
            def child = children.item(j)
            if (child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE) {
                parts.add(child.getNodeValue())
            }
        }
    }
    String faultText = parts.join(" ")
    List<String> named = authFields.findAll { name ->
        faultText =~ ("(?i)(?<![A-Za-z])" + name + "(?![A-Za-z])")
    }
    return "http=" + status + " outcome=" + errorCode + " soap_code=" + soapCode +
        " auth_fields_named=" + (named ? named.join(",") : "none") +
        " mentions_password=" + (faultText =~ "(?i)password" ? "yes" : "no")
}

def testCase = testRunner.testCase
String result = "RESULT not_sent: the sign step stopped before signing"
def requestStep = null
try {
    requestStep = testCase.getTestStepList().find { it.getClass().getSimpleName() == "WsdlTestRequestStep" }
    // SoapUI empties the response at the start of every run, so a response here is from this run.
    def response = requestStep == null ? null : requestStep.getTestRequest().getResponse()
    if (context.getProperty("signedThisRun") == "yes") {
        result = "RESULT " + classify(response, SOAP12, AUTH_FIELDS, ERROR_CODES) + " sp=" + context.getProperty("spSent")
    } else if (response != null) {
        result = "RESULT sent_unsigned: a request went out without the sign step"
    } else if (testCase.getPropertyValue("oneCallDone") == "yes" || System.getProperty("airtimesat.manualCheck.sent") == "yes") {
        result = "RESULT already_sent: this run sent nothing; the first RESULT line stands"
    }
} catch (Throwable error) {
    result = "RESULT unreadable: " + error.getClass().getSimpleName()
} finally {
    ["iwsUsername", "spAccount", "timestamp", "signature"].each { name -> testCase.setPropertyValue(name, "") }
    if (requestStep != null) {
        requestStep.getTestRequest().setRequestContent("NOT SIGNED: the call is done. Do not send.")
    }
    log.info("OK cleared the test case properties and the request text; the sent request stays in SoapUI's memory until you quit")
}
log.info(result)
