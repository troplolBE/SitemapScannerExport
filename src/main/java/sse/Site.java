package sse;

import burp.IRequestInfo;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class Site {

    private final IRequestInfo request;
    private final String comment;

    public Site(IRequestInfo request, String comment) {
        this.request = request;
        this.comment = comment;
    }

    public IRequestInfo getRequest() {
        return request;
    }

    public String getComment() {
        if (comment == null)
            return "";
        return comment;
    }

    public String to_print() {
        return request.getUrl().getProtocol() + "://" + request.getUrl().getHost() + request.getUrl().getPath() + " " +
                request.getUrl().getPort() + " " + comment + "\n";
    }

    public String[] to_csv(@NotNull List<String> options) {
        List<String> list = new ArrayList<>();
        list.add(request.getUrl().getProtocol() + "://" + request.getUrl().getHost() + request.getUrl().getPath());
        list.add(String.valueOf(request.getUrl().getPort()));
        if (options.contains("comment")) {
            list.add(getComment());
        }

        return new String[]{request.getUrl().getProtocol() + "://" + request.getUrl().getHost() +
                request.getUrl().getPath(), String.valueOf(request.getUrl().getPort()), comment};
    }

    public static String @NotNull [] get_csv_headers(@NotNull List<String> options) {
        List<String> list = new ArrayList<>(List.of("url", "port"));
        if (options.contains("comment")) {
            list.add("comment");
        }
        String[] headers = new String[list.size()];
        headers = list.toArray(headers);
        return headers;
    }

}
