package sse;

import burp.IRequestInfo;
import org.jetbrains.annotations.NotNull;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

public class Issue {

    private final String issueName;
    private final String issueDetail;
    private final URL url;
    private final String severity;
    private final ArrayList<IRequestInfo> messages;
    private final String confidence;

    public Issue(String issueName, String issueDetail, URL url, String severity, ArrayList<IRequestInfo> messages, String confidence) {
        this.issueName = issueName;
        this.issueDetail = issueDetail;
        this.url = url;
        this.severity = severity;
        this.messages = messages;
        this.confidence = confidence;
    }

    public String getIssueName() {
        return issueName;
    }

    public String getIssueDetail() {
        return issueDetail;
    }

    public URL getUrl() {
        return url;
    }

    public String getSeverity() {
        return severity;
    }

    public ArrayList<IRequestInfo> getMessages() {
        return messages;
    }

    public String getConfidence() {
        return confidence;
    }

    public String[] to_csv(@NotNull List<String> options) {
        List<String> list = new ArrayList<>();
        list.add(issueName);
        list.add(url.getProtocol() + "://" + url.getHost() + url.getPath());
        if (options.contains("issue_detail"))
            list.add(issueDetail);
        if (options.contains("severity"))
            list.add(severity);
        if (options.contains("confidence"))
            list.add(confidence);
        if (options.contains("messages")) {
            StringJoiner joiner = new StringJoiner("\n");
            for (IRequestInfo message : messages) {
                joiner.add(message.getMethod() + message.getUrl());
            }
            list.add(joiner.toString());
        }
        String[] data = new String[list.size()];
        return list.toArray(data);
    }

    public static String @NotNull [] get_csv_headers(@NotNull List<String> options) {
        List<String> list = new ArrayList<>(List.of("issue_name", "url"));
        if (options.contains("issue_detail"))
            list.add("issue_detail");
        if (options.contains("severity"))
            list.add("severity");
        if (options.contains("confidence"))
            list.add("confidence");
        if (options.contains("messages"))
            list.add("messages");
        String[] headers = new String[list.size()];
        return list.toArray(headers);
    }
}
