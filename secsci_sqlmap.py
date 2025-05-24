# ---------------------------------------
# Sec-Sci SQLMap v1.0.250524 - May 2025
# ---------------------------------------
# Tool:      Sec-Sci SQLMap v1.0.250524
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2025 WWW.SECURITY-SCIENCE.COM

from burp import IBurpExtender, ITab, IContextMenuFactory, IScannerListener, IScanIssue
from javax.swing import (
    JPanel, BoxLayout, JScrollPane, BorderFactory, Box, JLabel, JCheckBox, JSpinner, SpinnerNumberModel,
    JButton, JOptionPane, JMenuItem )
from javax.swing.border import EmptyBorder
from java.awt import FlowLayout, Dimension, BorderLayout, GridLayout, Font, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
from java.lang import Short
from java.util import ArrayList
from datetime import datetime
import subprocess, threading, os, re


sqlmap_options = []
request_file_ctr = 0


def run_sqlmap(sqlmap_cmd, request_url, request_file, messageInfo, httpService, callbacks):
    print('[INFO] SQLMap for {}'.format(request_url))
    print('[RUNNING] {}'.format(sqlmap_cmd))

    try:
        # sqlmap_output = subprocess.check_output(sqlmap_cmd, stderr=subprocess.STDOUT)
        sqlmap_output = subprocess.check_output(sqlmap_cmd, stderr=subprocess.STDOUT, shell=True,
                                                universal_newlines=True)
        # print('[!] SQLMap output\n{}'.format(sqlmap_output))
        result_filename = request_file + ".output"
        try:
            with open(result_filename, 'w') as f:
                # Write SQLMap Result
                f.write(sqlmap_output)
            print("[+] Exported SQLMap result to %s" % os.path.abspath(result_filename))

            extract_data = re.search(r"Parameter:.*?(?=\[\d{2}:\d{2}:\d{2}\] \[INFO\] fetched data logged to text files)",
                              sqlmap_output, re.DOTALL)

            if extract_data:
                extracted_data = extract_data.group(0)
                sqlmap_cmd_options = sqlmap_cmd.split('.request', 1)[-1].strip()
                # sqlmap_cmd_options = re.search(r'\.request\s+(.*)', sqlmap_cmd, re.DOTALL).group(1)
                issue_detail = """
                The web application was tested using SQLMap, an automated SQL injection and database takeover tool.
                This testing was conducted to verify a potential SQL injection vulnerability identified in the target
                endpoint..<br><br>Command used to verify the SQL injection vulnerability:
                <br><br><pre>python sqlmap.py -r host_sqlmap_timestamp.request """ + sqlmap_cmd_options + """</pre>
                <br>The following output from SQLMap provides technical details confirming the vulnerability:
                <br><br><pre>""" + "<br>".join(extracted_data.splitlines()) + """</pre><br>
                <br><b>Issue background</b><br><br>
                SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries
                in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their
                input appears and interfere with the structure of the surrounding query.<br><br>
                A wide range of damaging attacks can often be delivered via SQL injection, including reading or modifying
                critical application data, interfering with application logic, escalating privileges within the database
                and taking control of the database server.<br><br>
                <br><b>Issue remediation</b><br><br>
                The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as
                prepared statements) for all database access. This method uses two steps to incorporate potentially
                tainted data into SQL queries: first, the application specifies the structure of the query, leaving
                placeholders for each item of user input; second, the application specifies the contents of each
                placeholder. Because the structure of the query has already been defined in the first step, it is not
                possible for malformed data in the second step to interfere with the query structure. You should review
                the documentation for your database and application platform to determine the appropriate APIs which you
                can use to perform parameterized queries. It is strongly recommended that you parameterize every variable
                data item that is incorporated into database queries, even if it is not obviously tainted, to prevent
                oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base
                of the application.
                <ul><li>One common defense is to double up any single quotation marks appearing within user input before
                incorporating that input into a SQL query. This defense is designed to prevent malformed data from
                terminating the string into which it is inserted. However, if the data being incorporated into queries
                is numeric, then the defense may fail, because numeric data may not be encapsulated within quotes, in
                which case only a space is required to break out of the data context and interfere with the query.
                Further, in second-order SQL injection attacks, data that has been safely escaped when initially inserted
                into the database is subsequently read from the database and then passed back to it again. Quotation
                marks that have been doubled up initially will return to their original form when the data is reused,
                allowing the defense to be bypassed.</li>
                <li>Another often cited defense is to use stored procedures for database access. While stored procedures
                can provide security benefits, they are not guaranteed to prevent SQL injection attacks. The same kinds
                of vulnerabilities that arise within standard dynamic SQL queries can arise if any SQL is dynamically
                constructed within stored procedures. Further, even if the procedure is sound, SQL injection can arise
                if the procedure is invoked in an unsafe manner using user-controllable data.</li></ul>
                <br><b>References</b>
                <ul><li><a href="https://portswigger.net/web-security/sql-injection">Web Security Academy: SQL injection</a></li>
                <li><a href="https://support.portswigger.net/customer/portal/articles/1965677-using-burp-to-test-for-injection-flaws">Using Burp to Test for Injection Flaws</a></li>
                <li><a href="https://portswigger.net/web-security/sql-injection/cheat-sheet">Web Security Academy: SQL Injection Cheat Sheet</a></li></ul>
                <br><b>Vulnerability classifications</b>
                <ul><li><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/94.html">CWE-94: Improper Control of Generation of Code ('Code Injection')</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/116.html">CWE-116: Improper Encoding or Escaping of Output</a></li>
                <li><a href="https://capec.mitre.org/data/definitions/66.html">CAPEC-66: SQL Injection</a></li></ul>
                """

                issue = SSLScanIssue(
                    httpService,
                    request_url,
                    [messageInfo],
                    "[SecSci SQLMap Scan] SQL Injection",
                    issue_detail,
                    "High"
                )
                callbacks.addScanIssue(issue)
            else:
                print("[INFO] No SQL injection data found.")

            print("[DONE] SQLMap completed for {}".format(request_url))
        except Exception as e:
            print("[ERROR] Error writing file: %s" % str(e))
    except subprocess.CalledProcessError as e:
        print('[ERROR] Return code:', e.returncode)
        print(e.output)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IScannerListener):

    def wrap_with_padding(self, component):
        wrapper = JPanel()
        wrapper.setLayout(BoxLayout(wrapper, BoxLayout.Y_AXIS))
        wrapper.setBorder(EmptyBorder(0, 5, 3, 5))  # Vertical Spacing: top, left, bottom, right
        wrapper.add(component)
        return wrapper

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SecSci SQLMap")

        # Main Panel Scrollable
        self._main_panel = JPanel(BorderLayout())

        # Main Content Panel
        main_content = JPanel(GridBagLayout())
        main_content_gbc = GridBagConstraints()
        main_content_gbc.fill = GridBagConstraints.BOTH
        main_content_gbc.insets = Insets(5, 5, 5, 5)
        main_content_gbc.weightx = 1.0  # Make Columns Grow Horizontally
        main_content_gbc.weighty = 0.0  # No Vertical Stretching
        main_content.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3))

        panel_label_font = Font("Arial", Font.BOLD, 11)

        ### Detection Options ###
        detection_panel = JPanel()
        detection_panel.setLayout(GridLayout(0, 1, 3, 3))
        panel_title = BorderFactory.createTitledBorder("Detection Options")
        panel_title.setTitleFont(panel_label_font)
        detection_panel.setBorder(panel_title)

        label = JLabel("Level (1-5):")
        label.setFont(Font("Arial", Font.BOLD, 10))
        label.setAlignmentX(JLabel.LEFT_ALIGNMENT)
        detection_panel.add(self.wrap_with_padding(label))

        self.detection_level_spinner = JSpinner(SpinnerNumberModel(1, 1, 5, 1))
        self.detection_level_spinner.setMaximumSize(Dimension(Short.MAX_VALUE, 25))
        self.detection_level_spinner.setAlignmentX(JSpinner.LEFT_ALIGNMENT)
        detection_panel.add(self.wrap_with_padding(self.detection_level_spinner))

        label = JLabel("Risk (1-3):")
        label.setFont(Font("Arial", Font.BOLD, 10))
        label.setAlignmentX(JLabel.LEFT_ALIGNMENT)
        detection_panel.add(self.wrap_with_padding(label))

        self.detection_risk_spinner = JSpinner(SpinnerNumberModel(1, 1, 3, 1))
        self.detection_risk_spinner.setMaximumSize(Dimension(Short.MAX_VALUE, 25))
        self.detection_risk_spinner.setAlignmentX(JSpinner.LEFT_ALIGNMENT)
        detection_panel.add(self.wrap_with_padding(self.detection_risk_spinner))

        label = JLabel("Verbosity (0-6):")
        label.setFont(Font("Arial", Font.BOLD, 10))
        label.setAlignmentX(JLabel.LEFT_ALIGNMENT)
        detection_panel.add(self.wrap_with_padding(label))

        self.detection_verbosity_spinner = JSpinner(SpinnerNumberModel(1, 0, 6, 1))
        self.detection_verbosity_spinner.setMaximumSize(Dimension(Short.MAX_VALUE, 25))
        self.detection_verbosity_spinner.setAlignmentX(JSpinner.LEFT_ALIGNMENT)
        detection_panel.add(self.wrap_with_padding(self.detection_verbosity_spinner))

        ### Techniques Options ###
        techniques_panel = JPanel(GridLayout(0, 3, 3, 3))
        panel_title = BorderFactory.createTitledBorder("Techniques")
        panel_title.setTitleFont(Font("Arial", Font.BOLD, 12))
        techniques_panel.setBorder(panel_title)

        techniques_options = [
            ("Boolean-based (B)", "B"), ("Error-based (E)", "E"), ("Union-based (U)", "U"),
            ("Stacked (S)", "S"), ("Time-based (T)", "T"), ("Inline (Q)", "Q")
        ]

        self.techniques_checkboxes = []

        for techniques_label, techniques_value in techniques_options:
            self.techniques_checkbox = JCheckBox(techniques_label)
            self.techniques_checkbox.setFont(Font("Arial", Font.BOLD, 10))
            self.techniques_checkbox.setActionCommand(techniques_value)
            self.techniques_checkboxes.append(self.techniques_checkbox)
            techniques_panel.add(self.techniques_checkbox)

        ### Enumeration Options ###
        enumeration_panel = JPanel(GridLayout(0, 3, 3, 3))
        panel_title = BorderFactory.createTitledBorder("Enumeration")
        panel_title.setTitleFont(Font("Arial", Font.BOLD, 12))
        enumeration_panel.setBorder(panel_title)

        enumeration_options = [
            ("All (--all)", "--all.disabled"), ("Banner", "--banner"), ("Current User", "--current-user"),
            ("Current DB", "--current-db"), ("Hostname", "--hostname"), ("Users", "--users"),
            ("Passwords", "--passwords"), ("Privileges", "--privileges"), ("Roles", "--roles"),
            ("Databases", "--dbs"), ("Tables", "--tables"), ("Columns", "--columns"), ("Schema", "--schema"),
            ("Dump Data", "--dump")
        ]

        self.enumeration_checkboxes = []

        for enumeration_label, enumeration_value in enumeration_options:
            self.enumeration_checkbox = JCheckBox(enumeration_label)
            if "disabled" in enumeration_value: self.enumeration_checkbox.setEnabled(False)
            self.enumeration_checkbox.setFont(Font("Arial", Font.BOLD, 10))
            self.enumeration_checkbox.setActionCommand(enumeration_value)
            self.enumeration_checkboxes.append(self.enumeration_checkbox)
            enumeration_panel.add(self.enumeration_checkbox)

        ### Advanced Options ###
        advanced_panel = JPanel(GridLayout(0, 3, 3, 3))
        panel_title = BorderFactory.createTitledBorder("Advanced")
        panel_title.setTitleFont(Font("Arial", Font.BOLD, 12))
        advanced_panel.setBorder(panel_title)

        advanced_options = [
            ("OS Shell", "--os-shell"), ("OS Pwn", "--os-pwn.disabled"), ("Batch Mode", "--batch"),
            ("Flush Session", "--flush-session")
        ]

        self.advanced_checkboxes = []

        for advanced_label, advanced_value in advanced_options:
            self.advanced_checkbox = JCheckBox(advanced_label)
            if "disabled" in advanced_value: self.advanced_checkbox.setEnabled(False)
            self.advanced_checkbox.setFont(Font("Arial", Font.BOLD, 10))
            self.advanced_checkbox.setActionCommand(advanced_value)
            self.advanced_checkboxes.append(self.advanced_checkbox)
            advanced_panel.add(self.advanced_checkbox)

        ### Connection Options ###
        connection_panel = JPanel(GridLayout(0, 3, 3, 3))
        panel_title = BorderFactory.createTitledBorder("Connection Options")
        panel_title.setTitleFont(Font("Arial", Font.BOLD, 12))
        connection_panel.setBorder(panel_title)

        connection_options = [
            ("Use HTTPv2", "--http2"),("Imitate Smartphone", "--mobile"), ("Random User-Agent", "--random-agent"),
            ("Use Tor Network", "--tor.disabled"), ("Check Tor Usage", "--check-tor.disabled"),
            ("Force SSL/HTTPS", "--force-ssl")
        ]

        self.connection_checkboxes = []

        for connection_label, connection_value in connection_options:
            self.connection_checkbox = JCheckBox(connection_label)
            if "disabled" in connection_value: self.connection_checkbox.setEnabled(False)
            self.connection_checkbox.setFont(Font("Arial", Font.BOLD, 10))
            self.connection_checkbox.setActionCommand(connection_value)
            self.connection_checkboxes.append(self.connection_checkbox)
            connection_panel.add(self.connection_checkbox)

        ### Optimization Options ###
        optimization_panel = JPanel(GridLayout(0, 3, 3, 3))
        panel_title = BorderFactory.createTitledBorder("Optimization Options")
        panel_title.setTitleFont(Font("Arial", Font.BOLD, 12))
        optimization_panel.setBorder(panel_title)

        optimization_options = [
            ("Optimize (-o)", "-o"), ("Keep-Alive", "--keep-alive"), ("Output Prediction", "--predict-output"),
            ("Null Connection", "--null-connection")
        ]

        self.optimization_checkboxes = []

        for optimization_label, optimization_value in optimization_options:
            self.optimization_checkbox = JCheckBox(optimization_label)
            self.optimization_checkbox.setFont(Font("Arial", Font.BOLD, 10))
            self.optimization_checkbox.setActionCommand(optimization_value)
            self.optimization_checkboxes.append(self.optimization_checkbox)
            optimization_panel.add(self.optimization_checkbox)

        ### Save Settings ###
        save_settings_panel = JPanel(FlowLayout(FlowLayout.CENTER))

        default_button = JButton("Reset to Default Settings", actionPerformed=self.default_config)
        default_button.setFont(Font("Arial", Font.BOLD, 10))
        save_settings_panel.add(default_button)

        save_button = JButton("Save Settings", actionPerformed=self.save_config)
        save_button.setFont(Font("Arial", Font.BOLD, 10))
        save_settings_panel.add(save_button)

        load_button = JButton("Load Saved Settings", actionPerformed=self.load_config)
        load_button.setFont(Font("Arial", Font.BOLD, 10))
        save_settings_panel.add(load_button)

        """run_button = JButton("Run Test", actionPerformed=self.call_run_sqlmap)
        run_button.setFont(Font("Arial", Font.BOLD, 10))
        save_settings_panel.add(run_button)"""

        # Add Panels to Main Content Panel
        row = 0
        col = 0

        for i, panel in enumerate([enumeration_panel, detection_panel, techniques_panel, advanced_panel,
                                   connection_panel, optimization_panel, save_settings_panel]):
            main_content_gbc.gridx = col
            main_content_gbc.gridy = row
            main_content.add(panel, main_content_gbc)

            col += 1
            if col >= 2:
                col = 0
                row += 1

        # Wrap Main Content Panel in a Scroll Pane if UI is Taller than Screen
        main_panel_scroll = JScrollPane(main_content)
        self._main_panel.add(main_panel_scroll, BorderLayout.NORTH)
        self._main_panel.add(save_settings_panel, BorderLayout.CENTER)

        # Register for Tab Suite
        callbacks.addSuiteTab(self)
        # Register for Context Menu
        callbacks.registerContextMenuFactory(self)
        # Register for Scan Issue Notifications
        callbacks.registerScannerListener(self)

        print("[*] SecSci SQLMap loaded.")

        self.load_config(None)

    def getTabCaption(self):
        return "SecSci SQLMap Settings"

    def getUiComponent(self):
        return self._main_panel

    def createMenuItems(self, invocation):
        context_menu = ArrayList()
        action_listener = self._menuSQLMap(invocation, self._callbacks, self._helpers, self)

        context_menu_item = JMenuItem("SecSci SQLMap")
        context_menu_item.setActionCommand("SQLMap")
        context_menu_item.addActionListener(action_listener)
        context_menu.add(context_menu_item)

        return context_menu

    def httpMessageInfo(self, messageInfo):
        service = messageInfo.getHttpService()
        host = service.getHost()
        request_url = self._helpers.analyzeRequest(messageInfo).getUrl()
        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = request_info.getHeaders()
        body_bytes = messageInfo.getRequest()[request_info.getBodyOffset():]
        body = ''.join([chr((b + 256) % 256) for b in body_bytes])

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        request_file = "Results/{}_sqlmap_{}".format(host, timestamp)
        try:
            with open(request_file + ".request", 'w') as f:
                # Writing HTTP Request
                f.write(headers[0] + "\r\n")
                for header in headers[1:]:
                    f.write(header + "\r\n")
                f.write("\r\n")
                f.write(body)
            print("[+] Exported HTTP Request to %s.request" % os.path.abspath(request_file))
        except Exception as e:
            print("[!] Error writing file: %s" % str(e))
            return

        sqlmap_options_str = " ".join(sqlmap_options)
        sqlmap_cmd = 'python "{0}" -r {1}.request {2} --output-dir={1}'.format(os.environ.get("sqlmap", None),
                                                           request_file, sqlmap_options_str)

        thread = threading.Thread(target=run_sqlmap,
                                  args=(sqlmap_cmd, request_url, request_file, messageInfo, service, self._callbacks))
        thread.start()

    def newScanIssue(self, issue):
        filter_url_contains = ""
        filter_issue_name_contains = "SQL Injection" # "SQL Injection"
        filter_severity = ""  # Example: "High", "Medium", "Low", etc.
        filter_confidence = ""  # Example: "Certain", "Firm", "Tentative"

        issue_url = str(issue.getUrl())
        issue_name = issue.getIssueName()
        issue_severity = issue.getSeverity()
        issue_confidence = issue.getConfidence()

        if "secsci sqlmap" in issue_name.lower():
            return

        if not ((filter_url_contains.lower() in issue_url.lower() if filter_url_contains else True)
                and (filter_issue_name_contains.lower() in issue_name.lower() if filter_issue_name_contains else True)
                and (issue_severity == filter_severity if filter_severity else True)
                and (issue_confidence == filter_confidence if filter_confidence else True)):
            return

        http_messages = issue.getHttpMessages()

        self.httpMessageInfo(http_messages[len(http_messages)-1])
        """for i, messageInfo in enumerate(http_messages):
            self.httpMessageInfo(messageInfo)"""

    class _menuSQLMap(ActionListener):
        def __init__(self, invocation, callbacks, helpers, burp_extender):
            self._invocation = invocation
            self._callbacks = callbacks
            self._helpers = helpers
            self._extender = burp_extender

        def actionPerformed(self, event):
            action_command = event.getActionCommand()
            selected_messages = self._invocation.getSelectedMessages()

            if selected_messages:
                for messageInfo in selected_messages:
                    request_url = self._helpers.analyzeRequest(messageInfo).getUrl()
                    if not self._callbacks.isInScope(request_url):
                        continue_scan = JOptionPane.showConfirmDialog(
                            None,
                            "{}\nContinue SQLMap Scan?".format(request_url),
                            "Out of Scope URL",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE)

                        if continue_scan == JOptionPane.YES_OPTION:
                            print("[INFO] {} is not In-Scope: SQLMap scan initiated.".format(request_url))
                        else:
                            print("[INFO] {} is not In-Scope: SQLMap scan is cancelled.".format(request_url))
                    else:
                        continue_scan = JOptionPane.YES_OPTION

                    if continue_scan == JOptionPane.YES_OPTION:
                        self._extender.httpMessageInfo(messageInfo)

    def default_config(self, event):
        default_settings = {"--dbs":"1", "--batch":"1", "--flush-session":"1", "--random-agent":"1", "-o":"1"}

        self.detection_level_spinner.setValue(1)
        self.detection_risk_spinner.setValue(1)
        self.detection_verbosity_spinner.setValue(1)

        for checkboxes in [self.techniques_checkboxes, self.enumeration_checkboxes, self.advanced_checkboxes,
                           self.connection_checkboxes, self.optimization_checkboxes]:
            for cb in checkboxes:
                cb.setSelected(default_settings.get(cb.getActionCommand(), "0") == "1")

    def load_config(self, event):
        sqlmap_options[:] = []
        config_file_path = os.path.join(os.getcwd(), "sqlmap.conf")
        if not os.path.exists(config_file_path):
            print("Config file not found. Skipping load.")
            # This will potentially unload the extension
            raise RuntimeError("Config file not found. Skipping load.")
        try:
            config = {}
            with open(config_file_path, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, val = line.strip().split('=', 1)
                        config[key] = val
            self.detection_level_spinner.setValue(int(config.get("detection_level", 1)))
            sqlmap_options.append("--level={}".format(self.detection_level_spinner.getValue()))
            self.detection_risk_spinner.setValue(int(config.get("detection_risk", 1)))
            sqlmap_options.append("--risk={}".format(self.detection_risk_spinner.getValue()))
            self.detection_verbosity_spinner.setValue(int(config.get("-v", 1)))
            sqlmap_options.append("-v {}".format(self.detection_verbosity_spinner.getValue()))
            technique = ""
            for checkboxes in [self.techniques_checkboxes, self.enumeration_checkboxes, self.advanced_checkboxes,
                               self.connection_checkboxes, self.optimization_checkboxes]:
                for cb in checkboxes:
                    cb.setSelected(config.get(cb.getActionCommand(), "0") == "1")
                    if cb.isSelected():
                        if str(cb.getActionCommand()) in ["B", "E", "U", "S", "T", "Q"]:
                            technique = technique + str(cb.getActionCommand())
                        else:
                            sqlmap_options.append(str(cb.getActionCommand()))
            if technique:
                sqlmap_options.append("--technique={}".format(technique))

            print("[!] Config loaded from {}".format(config_file_path))
        except Exception as e:
            print("[e] Error loading config: {}".format(e))
            raise RuntimeError("Config file not found. Skipping load.")

    def save_config(self, event):
        sqlmap_options[:] = []
        config_file_path = os.path.join(os.getcwd(), "sqlmap.conf")

        try:
            with open(config_file_path, 'w') as f:
                ### Detection Options ###
                f.write("--level=%s\n" % self.detection_level_spinner.getValue())
                sqlmap_options.append("--level={}".format(self.detection_level_spinner.getValue()))
                f.write("--risk=%s\n" % self.detection_risk_spinner.getValue())
                sqlmap_options.append("--risk={}".format(self.detection_risk_spinner.getValue()))
                f.write("-v=%s\n" % self.detection_verbosity_spinner.getValue())
                sqlmap_options.append("-v {}".format(self.detection_verbosity_spinner.getValue()))

                ### All Chekboxes ###
                technique = ""
                for checkboxes in [self.techniques_checkboxes, self.enumeration_checkboxes, self.advanced_checkboxes,
                                   self.connection_checkboxes, self.optimization_checkboxes]:
                    for cb in checkboxes:
                        key = cb.getActionCommand()
                        f.write("%s=%s\n" % (key, "1" if cb.isSelected() else "0"))
                        if cb.isSelected():
                            if str(cb.getActionCommand()) in ["B", "E", "U", "S", "T", "Q"]:
                                technique = technique + str(cb.getActionCommand())
                            else:
                                sqlmap_options.append(str(cb.getActionCommand()))
                if technique:
                    sqlmap_options.append("--technique={}".format(technique))

                print("[!] Config saved at {} successfully!".format(config_file_path))
                JOptionPane.showMessageDialog(None, "Configuration saved at {} successfully!".format(config_file_path),
                                              "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            print("[e] Error saving configuration. {}".format(e))
            JOptionPane.showMessageDialog(None, "Error saving configuration. {}".format(e),
                                          "Error", JOptionPane.ERROR_MESSAGE)


class SSLScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Certain"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService