package burp.Logs;

import burp.BurpExtender;
import burp.Highlighter.Highlighter;
import burp.IHttpRequestResponsePersisted;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.awt.Color;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class LogEntry {
  private String extractDateHeaderValue(IHttpRequestResponsePersisted requestResponse) {
    // Analyze the response to get IResponseInfo object
    IResponseInfo analyzedResponse = BurpExtender.getHelpers().analyzeResponse(requestResponse.getResponse());

    // Get the headers from the IResponseInfo object
    List<String> responseHeaders = analyzedResponse.getHeaders();

    // Find and extract the "Date" header value
    String timeValue = null;
    for (String header : responseHeaders) {
      if (header.startsWith("Date: ")) {
        // Extract the value of the "Date" header
        String fullDate = header.substring("Date: ".length());

        // Parse the full date to obtain the time
        try {
          SimpleDateFormat fullDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss");
          Date date = fullDateFormat.parse(fullDate);

          // Format the Date as just the time
          SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
          timeValue = timeFormat.format(date);
        } catch (Exception e) {
          // Handle parsing errors
          timeValue = "Invalid Time";
        }
        break;
      }
    }

    return timeValue;
  }

  private long requestResponseId;
  private IHttpRequestResponsePersisted originalRequestResponse;
  private IHttpRequestResponsePersisted modifiedRequestResponse;

  private URL originalURL;
  private URL modifiedURL;

  private String originalMethod;
  private String modifiedMethod;

  private int originalLength;

  private int modifiedLength;
  private int lengthDifference;
  private double responseDistance;

  private int originalResponseStatus;
  private int modifiedResponseStatus;

  private int originalRequestHashCode;
  private int modifiedRequestHashCode;

  private int toolFlag;

  private long requestSentTime;

  private String reqestSentTimeX;

  private Color backgroundColor;
  private Color selectedBackgroundColor;

  public long getRequestResponseId() {
    return requestResponseId;
  }

  public Color getSelectedBackgroundColor() {
    return this.selectedBackgroundColor;
  }

  public void setBackgroundColor(Color backgroundColor, Color selectedBackgroundColor) {
    this.backgroundColor = backgroundColor;
    this.selectedBackgroundColor = selectedBackgroundColor;
  }

  public Color getBackgroundColor() { return this.backgroundColor; }

  public Color getFontColor() { return this.backgroundColor; }

  public void setRequestResponseId(long requestResponseId) {
    this.requestResponseId = requestResponseId;
  }

  public IHttpRequestResponsePersisted getOriginalRequestResponse() {
    return originalRequestResponse;
  }

  public void setOriginalRequestResponse(IHttpRequestResponsePersisted originalRequestResponse) {
    this.originalRequestResponse = originalRequestResponse;
  }

  public String getOriginalDateHeaderValue() {
    return extractDateHeaderValue(originalRequestResponse);
  }

  public String getModifiedDateHeaderValue() {
    return extractDateHeaderValue(modifiedRequestResponse);
  }
  public IHttpRequestResponsePersisted getModifiedRequestResponse() {
    return modifiedRequestResponse;
  }

  public void setModifiedRequestResponse(IHttpRequestResponsePersisted modifiedRequestResponse) {
    this.modifiedRequestResponse = modifiedRequestResponse;
  }

  public URL getOriginalURL() {
    return originalURL;
  }

  public void setOriginalURL(URL originalURL) {
    this.originalURL = originalURL;
  }

  public URL getModifiedURL() {
    return modifiedURL;
  }

  public void setModifiedURL(URL modifiedURL) {
    this.modifiedURL = modifiedURL;
  }

  public int getOriginalRequestHashCode() {
    return originalRequestHashCode;
  }

  public int getModifiedRequestHashCode() {
    return modifiedRequestHashCode;
  }

  public long getRequestSentTime() {
    return requestSentTime;
  }

  public String getOriginalMethod() {
    return originalMethod;
  }

  public void setOriginalMethod(String originalMethod) {
    this.originalMethod = originalMethod;
  }

  public String getModifiedMethod() {
    return modifiedMethod;
  }

  public void setModifiedMethod(String modifiedMethod) {
    this.modifiedMethod = modifiedMethod;
  }

  public int getOriginalLength() {
    return originalLength;
  }

  public void setOriginalLength(int originalLength) {
    this.originalLength = originalLength;
  }

  public int getModifiedLength() {
    return modifiedLength;
  }

  public void setModifiedLength(int modifiedLength) {
    this.modifiedLength = modifiedLength;
  }

  public int getLengthDifference() {
    return lengthDifference;
  }

  public void setLengthDifference(int lengthDifference) {
    this.lengthDifference = lengthDifference;
  }

  public double getResponseDistance() {
    return responseDistance;
  }

  public void setResponseDistance(double responseDistance) {
    this.responseDistance = responseDistance;
  }

  public int getOriginalResponseStatus() {
    return originalResponseStatus;
  }

  public void setOriginalResponseStatus(int originalResponseStatus) {
    this.originalResponseStatus = originalResponseStatus;
  }

  public int getModifiedResponseStatus() {
    return modifiedResponseStatus;
  }

  public void setModifiedResponseStatus(int modifiedResponseStatus) {
    this.modifiedResponseStatus = modifiedResponseStatus;
  }

  public void setOriginalRequestHashCode(int originalRequestHashCode) {
    this.originalRequestHashCode = originalRequestHashCode;
  }

  public void setModifiedRequestHashCode(int modifiedRequestHashCode) {
    this.modifiedRequestHashCode = modifiedRequestHashCode;
  }

  public void setRequestSentTime(long requestSentTime) {
    this.requestSentTime = requestSentTime;
  }

  public String getFormattedRequestSentTime() {
    try {
      Date date = new Date(requestSentTime);
      SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");
      return sdf.format(date);
    } catch (Exception e) {
      return "Invalid Timestamp";
    }
  }

  public long getTimeDifference() {
    String originalTime = getOriginalDateHeaderValue();
    String modifiedTime = getModifiedDateHeaderValue();

    if (originalTime != null && modifiedTime != null) {
      SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
      try {
        Date originalDate = sdf.parse(originalTime);
        Date modifiedDate = sdf.parse(modifiedTime);

        // Calculate the time difference in milliseconds
        return Math.abs(originalDate.getTime() - modifiedDate.getTime());
      } catch (ParseException e) {
        throw new RuntimeException(e);
      }
    }

    return -1; // Return -1 in case of errors or missing time values
  }

  //#, Host, Method, URL, Status, Length
  // #
  // Host
  // Orig. Method
  // Mod. Method
  // Orig. URL
  // Mod. URL
  // Orig. Status
  // Mod. Status
  // Orig. Length
  // Mod. Length

  public LogEntry(long requestResponseId,
                  int toolFlag,
                  IHttpRequestResponsePersisted originalRequestResponse,
                  IHttpRequestResponsePersisted modifiedRequestResponse) {

    IRequestInfo originalAnalyzedRequest = BurpExtender.getHelpers()
            .analyzeRequest(originalRequestResponse);

    IRequestInfo modifiedAnalyzedRequest = BurpExtender.getHelpers()
            .analyzeRequest(modifiedRequestResponse);

    IResponseInfo originalAnalyzedResponse = BurpExtender.getHelpers()
            .analyzeResponse(originalRequestResponse.getResponse());
    this.originalResponseStatus = originalAnalyzedResponse.getStatusCode();

    IResponseInfo modifiedAnalyzedResponse = BurpExtender.getHelpers()
            .analyzeResponse(modifiedRequestResponse.getResponse());
    this.modifiedResponseStatus = modifiedAnalyzedResponse.getStatusCode();

    // Request ID
    this.requestResponseId = requestResponseId;

    // Original Request Info
    this.originalRequestResponse = originalRequestResponse;
    this.originalURL = originalAnalyzedRequest.getUrl();
    this.originalMethod = originalAnalyzedRequest.getMethod();
    this.originalLength = originalRequestResponse.getResponse().length;

    // Modified Request Info
    this.modifiedRequestResponse = modifiedRequestResponse;
    this.modifiedURL = modifiedAnalyzedRequest.getUrl();
    this.modifiedMethod = modifiedAnalyzedRequest.getMethod();
    this.modifiedLength = modifiedRequestResponse.getResponse().length;

    // Comparisons
    this.lengthDifference = Math.abs(this.originalLength - this.modifiedLength);
    this.responseDistance = 0;

    this.originalRequestHashCode = Arrays.hashCode(originalRequestResponse.getRequest());
    this.modifiedRequestHashCode = Arrays.hashCode(modifiedRequestResponse.getRequest());

    this.toolFlag = toolFlag;

    this.requestSentTime = System.currentTimeMillis();

    backgroundColor = Highlighter.COLORS[0];
    selectedBackgroundColor = Highlighter.SELECTED_COLORS[0];
  }

  public int getToolFlag() {
    return toolFlag;
  }

  public void setToolFlag(int toolFlag) {
    this.toolFlag = toolFlag;
  }
}

