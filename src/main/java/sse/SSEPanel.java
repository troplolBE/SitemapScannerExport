package sse;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import com.opencsv.CSVWriter;
import com.opencsv.ICSVWriter;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class SSEPanel extends JPanel {

    private final transient IBurpExtenderCallbacks callbacks;
    private final List<String> options;
    private JComboBox<String> delimiters;
    private JCheckBox outer_scope;
    private JCheckBox st_only;
    private JCheckBox sc_only;
    private JTextField dirField;
    private String filepath;

    public SSEPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.options = new ArrayList<>();

        initComponents();
    }

    private void initComponents() {
        GroupLayout layout = new GroupLayout(this);

        JLabel titleLabel = new JLabel("Sitemap Exporter");
        titleLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
        titleLabel.setForeground(new Color(235, 136, 0));
        JLabel description = new JLabel("Sitemap Exporter exports all the content from the burp scanner to a csv file. You can decide some configuration options for the exported data.");
        description.setFont(new Font("Tahoma", Font.PLAIN, 12));
        JLabel format = new JLabel("Please select the delimiter you desire for your csv file:");
        format.setFont(new Font("Tahoma", Font.PLAIN, 12));
        this.delimiters = new JComboBox<>(new String[]{";", ",", "|", "space"});
        JLabel dir = new JLabel("Select a file and directory to save the data:");
        dir.setFont(new Font("Tahoma", Font.PLAIN, 12));
        this.dirField = new JTextField();
        JButton select_dir = new JButton("Choose file");
        select_dir.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    chooseFile();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        });
        // Options
        JLabel optionsLabel = new JLabel("Export options:");
        optionsLabel.setFont(new Font("Tahoma", Font.BOLD, 14));
        optionsLabel.setForeground(new Color(235, 136, 0));
        // general options
        JLabel g_opt = new JLabel("General:");
        g_opt.setFont(new Font("Tahoma", Font.PLAIN, 14));
        this.outer_scope = new JCheckBox("Include data from outer scope ?");
        this.st_only = new JCheckBox("Export only the sitemap", true);
        this.st_only.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if ((st_only.isSelected()) && (sc_only.isSelected())) {
                    sc_only.setSelected(false);
                }
            }
        });
        this.sc_only = new JCheckBox("Export only the scan issues");
        this.sc_only.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if ((sc_only.isSelected()) && (st_only.isSelected())) {
                    st_only.setSelected(false);
                }
            }
        });
        // Sitemap options
        JLabel site_opt = new JLabel("Sitemap:");
        site_opt.setFont(new Font("Tahoma", Font.PLAIN, 14));
        JCheckBox exp_com_opt = new JCheckBox("Export comment");
        exp_com_opt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (exp_com_opt.isSelected()) {
                    options.add("comment");
                } else {
                    options.remove("comment");
                }
            }
        });
        // Scan issues options
        JLabel scan_opt = new JLabel("Scan issues:");
        scan_opt.setFont(new Font("Tahoma", Font.PLAIN, 14));
        JCheckBox exp_idet_opt = new JCheckBox("Export issue detail");
        exp_idet_opt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (exp_idet_opt.isSelected()) {
                    options.add("issue_detail");
                } else {
                    options.remove("issue_detail");
                }
            }
        });
        JCheckBox exp_sev_opt = new JCheckBox("Export severity");
        exp_sev_opt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (exp_sev_opt.isSelected()) {
                    options.add("severity");
                } else {
                    options.remove("severity");
                }
            }
        });
        JCheckBox exp_con_opt = new JCheckBox("Export confidence");
        exp_con_opt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (exp_con_opt.isSelected()) {
                    options.add("confidence");
                } else {
                    options.remove("confidence");
                }
            }
        });
        JCheckBox exp_msg_opt = new JCheckBox("Export other urls", true);
        exp_msg_opt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (exp_msg_opt.isSelected()) {
                    options.add("messages");
                } else {
                    options.remove("messages");
                }
            }
        });
        JButton export = new JButton("Export");
        export.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!checkData()) {
                    return;
                }
                char delimiter = delimiters.getSelectedItem().toString().charAt(0);
                if (delimiter == 's') {
                    delimiter = ' ';
                }
                if (st_only.isSelected()) {
                    try {
                        save_sitemap(delimiter);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                } else {
                    try {
                        save_issues(delimiter);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });
        this.filepath = "";

        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup().addGap(15)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(titleLabel)
                                        .addComponent(description)
                                        .addComponent(format)
                                        .addComponent(delimiters, GroupLayout.PREFERRED_SIZE, 80,
                                                GroupLayout.PREFERRED_SIZE)
                                        .addComponent(dir)
                                        .addComponent(dirField, GroupLayout.PREFERRED_SIZE, 350,
                                                GroupLayout.PREFERRED_SIZE)
                                        .addComponent(select_dir)
                                        .addComponent(optionsLabel)
                                        .addComponent(g_opt)
                                        .addComponent(outer_scope)
                                        .addComponent(st_only)
                                        .addComponent(sc_only)
                                        .addComponent(site_opt)
                                        .addComponent(exp_com_opt)
                                        .addComponent(scan_opt)
                                        .addComponent(exp_idet_opt)
                                        .addComponent(exp_sev_opt)
                                        .addComponent(exp_con_opt)
                                        .addComponent(exp_msg_opt)
                                        .addComponent(export)
                                )
                        )
        );

        layout.setVerticalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addGap(15)
                                .addComponent(titleLabel).addGap(15)
                                .addComponent(description).addGap(15)
                                .addComponent(format).addGap(15)
                                .addComponent(delimiters, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                        GroupLayout.PREFERRED_SIZE)
                                .addGap(15)
                                .addComponent(dir).addGap(15)
                                .addComponent(dirField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
                                        GroupLayout.PREFERRED_SIZE)
                                .addGap(15)
                                .addComponent(select_dir).addGap(25)
                                .addComponent(optionsLabel).addGap(15)
                                .addComponent(g_opt).addGap(15)
                                .addComponent(outer_scope).addGap(15)
                                .addComponent(st_only).addGap(15)
                                .addComponent(sc_only).addGap(15)
                                .addComponent(site_opt).addGap(15)
                                .addComponent(exp_com_opt).addGap(15)
                                .addComponent(scan_opt).addGap(15)
                                .addComponent(exp_idet_opt).addGap(15)
                                .addComponent(exp_sev_opt).addGap(15)
                                .addComponent(exp_con_opt).addGap(15)
                                .addComponent(exp_msg_opt).addGap(15)
                                .addComponent(export)
                        )
        );

        this.setLayout(layout);
    }

    private void chooseFile() throws IOException {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setFileFilter(new FileNameExtensionFilter("CSV", ".csv"));
        chooser.setAcceptAllFileFilterUsed(false);
        chooser.setDialogTitle("Please select a file to save");
        int dialog = chooser.showSaveDialog(this);

        if (dialog == JFileChooser.APPROVE_OPTION) {
            String filename = chooser.getSelectedFile().getCanonicalPath();
            callbacks.printOutput(filename);
            if (filename.length() > 4) {
                String extension = filename.substring(filename.length() - 4);
                if (extension.charAt(0) != '.') {
                    filename = filename + ".csv";
                }
                if (!extension.equals(".csv")) {
                    filename = filename.substring(0, filename.length() - 4) + ".csv";
                }
            }
            this.dirField.setText(filename);
            this.filepath = filename;
        }
    }

    private void alert(String str) {
        JOptionPane.showMessageDialog(this, str, "INFO", JOptionPane.INFORMATION_MESSAGE);
    }

    private boolean checkData() {
        if (filepath.isEmpty() || filepath.isBlank()) {
            alert("No file selected. Please select one !");
            return false;
        }
        if (st_only.isSelected() && callbacks.getSiteMap("").length == 0) {
            alert("No sites in sitemap :/");
            return false;
        }
        if (sc_only.isSelected() && callbacks.getScanIssues("").length == 0) {
            alert("No scan issues :/");
            return false;
        }
        return true;
    }

    private void save_sitemap(char delimiter) throws IOException {
        ArrayList<Site> sites = new ArrayList<>();
        for (IHttpRequestResponse site : callbacks.getSiteMap("")) {
            Site request = new Site(callbacks.getHelpers().analyzeRequest(site), site.getComment());
            sites.add(request);
        }
        // Remove sites out of scope
        if (!outer_scope.isSelected()) {
            ArrayList<Site> clean_sites = new ArrayList<>();
            for (Site req : sites) {
                if (callbacks.isInScope(req.getRequest().getUrl())) {
                    callbacks.printOutput("URL out of scope");
                    clean_sites.add(req);
                }
            }
            sites = clean_sites;
        }

        //remove duplicates (not sure this is useful)
        ArrayList<URL> clean_urls = new ArrayList<>();
        ArrayList<Site> no_duplicates = new ArrayList<>();
        for (Site req : sites) {
            if (!clean_urls.contains(req.getRequest().getUrl())) {
                clean_urls.add(req.getRequest().getUrl());
                no_duplicates.add(req);
            }
        }
        sites = no_duplicates;

        if (sites.size() <= 0) {
            alert("No sites left to export :/");
        }

        // Write to csv file
        CSVWriter writer = new CSVWriter(new FileWriter(filepath), delimiter, '"', ICSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);
        writer.writeNext(Site.get_csv_headers(options));
        for (Site site : sites) {
            callbacks.printOutput(site.to_print());
            writer.writeNext(site.to_csv(options));
        }
        writer.close();
    }

    private void save_issues(char delimiter) throws IOException {
        ArrayList<Issue> issues = new ArrayList<>();
        for (IScanIssue scanIssue : callbacks.getScanIssues("")) {
            ArrayList<IRequestInfo> messages = new ArrayList<>();
            for (IHttpRequestResponse req : scanIssue.getHttpMessages()) {
                messages.add(callbacks.getHelpers().analyzeRequest(req));
            }
            Issue issue = new Issue(scanIssue.getIssueName(), scanIssue.getIssueDetail(), scanIssue.getUrl(),
                    scanIssue.getSeverity(), messages, scanIssue.getConfidence());
            issues.add(issue);
        }

        // Remove out of scope issues
        if (!outer_scope.isSelected()) {
            ArrayList<Issue> clean_issues = new ArrayList<>();
            for (Issue issue : issues) {
                if (callbacks.isInScope(issue.getUrl())) {
                    callbacks.printOutput("URL out of scope");
                    clean_issues.add(issue);
                }
            }
            issues = clean_issues;
        }

        // Remove duplicates if any
        ArrayList<URL> clean_urls = new ArrayList<>();
        ArrayList<Issue> no_duplicates = new ArrayList<>();
        for (Issue issue : issues) {
            if (!clean_urls.contains(issue.getUrl())) {
                clean_urls.add(issue.getUrl());
                no_duplicates.add(issue);
            }
        }
        issues = no_duplicates;

        // Write to csv file
        CSVWriter writer = new CSVWriter(new FileWriter(filepath), delimiter, '"', ICSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);
        writer.writeNext(Issue.get_csv_headers(options));
        for (Issue issue : issues) {
            writer.writeNext(issue.to_csv(options));
        }
        writer.close();
    }
}