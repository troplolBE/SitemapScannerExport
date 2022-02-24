package burp;

import sse.SSEPanel;

import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

    private SSEPanel visual;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        callbacks.printOutput("Loading extension !");
        this.visual = new SSEPanel(callbacks);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Sitemap & Scanner Export");
        callbacks.addSuiteTab(this);
        callbacks.printOutput("Loaded extension !");
    }

    @Override
    public String getTabCaption() {
        return "Sitemap & Scanner Export";
    }

    @Override
    public Component getUiComponent() {
        return visual;
    }

    @Override
    public void extensionUnloaded() {
        this.callbacks.printOutput("Unloaded extension");
    }
}
