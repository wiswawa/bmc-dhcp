import AppKit
import WebKit

// The native shell stays unprivileged. The bundled launcher requests system
// authorization for the network backend, and prints its local session URL.
@MainActor
final class Desktop: NSObject, NSApplicationDelegate, NSWindowDelegate,
    WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    private var window: NSWindow!
    private var webView: WKWebView!
    private var overlay: NSView!
    private var message: NSTextField!
    private var spinner: NSProgressIndicator!
    private var retryButton: NSButton!
    private var launchProcess: Process?
    private var sessionURL: URL?
    private var terminating = false
    private var launchComplete = false
    private var quitAfterLaunch = false
    private let logURL = URL(fileURLWithPath: ProcessInfo.processInfo.environment["BMCD_HOME"]
                            ?? FileManager.default.homeDirectoryForCurrentUser.path, isDirectory: true)
        .appendingPathComponent("Library/Logs/BMC DHCP.log")

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        buildWindow()
        launchBackend()
        NSApp.activate(ignoringOtherApps: true)
    }

    private func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "关于 BMC DHCP", action: #selector(about), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "隐藏 BMC DHCP", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出 BMC DHCP", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        main.addItem(appItem)

        let editItem = NSMenuItem()
        let edit = NSMenu(title: "编辑")
        for (title, selector, key) in [
            ("撤销", "undo:", "z"), ("剪切", "cut:", "x"),
            ("复制", "copy:", "c"), ("粘贴", "paste:", "v"), ("全选", "selectAll:", "a")
        ] {
            edit.addItem(withTitle: title, action: Selector(selector), keyEquivalent: key)
        }
        editItem.submenu = edit
        main.addItem(editItem)

        let windowItem = NSMenuItem()
        let windows = NSMenu(title: "窗口")
        windows.addItem(withTitle: "最小化", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        windows.addItem(withTitle: "缩放", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windowItem.submenu = windows
        main.addItem(windowItem)
        NSApp.windowsMenu = windows

        let helpItem = NSMenuItem()
        let help = NSMenu(title: "帮助")
        help.addItem(withTitle: "连接 BMC", action: #selector(showHelp), keyEquivalent: "?")
        help.addItem(withTitle: "打开运行日志", action: #selector(openLog), keyEquivalent: "")
        helpItem.submenu = help
        main.addItem(helpItem)
        NSApp.mainMenu = main
    }

    private func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1240, height: 860),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "BMC DHCP"
        window.subtitle = "Mac 直连 BMC · 临时 DHCP"
        window.minSize = NSSize(width: 960, height: 720)
        window.appearance = NSAppearance(named: .darkAqua)
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.center()

        let config = WKWebViewConfiguration()
        if ProcessInfo.processInfo.arguments.contains("--no-elevate") {
            // QA must not read or overwrite the real user's saved form values.
            config.websiteDataStore = .nonPersistent()
        }
        config.userContentController.add(self, name: "bmcdDesktop")
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.translatesAutoresizingMaskIntoConstraints = false
        let content = window.contentView!
        content.addSubview(webView)
        NSLayoutConstraint.activate([
            webView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            webView.topAnchor.constraint(equalTo: content.topAnchor),
            webView.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        overlay = NSView()
        overlay.wantsLayer = true
        overlay.layer?.backgroundColor = NSColor(calibratedWhite: 0.06, alpha: 1).cgColor
        overlay.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(overlay)
        NSLayoutConstraint.activate([
            overlay.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            overlay.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            overlay.topAnchor.constraint(equalTo: content.topAnchor),
            overlay.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])
        let title = NSTextField(labelWithString: "BMC DHCP")
        title.font = .systemFont(ofSize: 28, weight: .semibold)
        spinner = NSProgressIndicator()
        spinner.style = .spinning
        spinner.controlSize = .regular
        message = NSTextField(wrappingLabelWithString: "正在启动本地服务…\n请在系统授权窗口中允许临时配置 BMC 网口。")
        message.alignment = .center
        message.textColor = .secondaryLabelColor
        message.font = .systemFont(ofSize: 14)
        message.widthAnchor.constraint(equalToConstant: 560).isActive = true
        retryButton = NSButton(title: "重新启动", target: self, action: #selector(retryLaunch))
        retryButton.isHidden = true
        let logs = NSButton(title: "打开运行日志", target: self, action: #selector(openLog))
        let stack = NSStackView(views: [title, spinner, message, retryButton, logs])
        stack.orientation = .vertical
        stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        overlay.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: overlay.centerYAnchor)
        ])
        window.makeKeyAndOrderFront(nil)
    }

    @objc private func retryLaunch() {
        if launchComplete, let url = sessionURL {
            webView.load(URLRequest(url: url))
            return
        }
        guard launchProcess?.isRunning != true else { return }
        launchBackend()
    }

    private func launchBackend() {
        guard let resources = Bundle.main.resourceURL else { return }
        let executable = resources.appendingPathComponent("backend/bmcd-runtime")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            showError("应用缺少随包运行时，请重新构建或完整解压 BMC DHCP.app。")
            return
        }
        overlay.isHidden = false
        retryButton.isHidden = true
        spinner.startAnimation(nil)
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--gui", "none", "--keep"]
        var environment = ProcessInfo.processInfo.environment
        environment["BMCD_NATIVE"] = "1"
        process.environment = environment
        if ProcessInfo.processInfo.arguments.contains("--no-elevate") {
            // Developer smoke checks can open the real app without configuring a NIC.
            process.arguments?.append("--no-elevate")
        }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice // launcher writes its own log
        launchProcess = process
        launchComplete = false
        do {
            try process.run()
        } catch {
            pipe.fileHandleForWriting.closeFile()
            launchProcess = nil
            showError("无法启动随包运行时：\(error.localizedDescription)")
            return
        }
        // The parent must release its write end, or readDataToEndOfFile never completes.
        pipe.fileHandleForWriting.closeFile()
        DispatchQueue.global(qos: .userInitiated).async {
            let output = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let text = String(data: output, encoding: .utf8) ?? ""
            Task { @MainActor in
                self.launchProcess = nil
                guard process.terminationStatus == 0,
                      let url = text.split(separator: "\n").compactMap({ URL(string: String($0)) })
                        .first(where: { Self.validSessionURL($0) }) else {
                    self.showError("本地服务未能启动。授权取消或启动错误的详情见运行日志。")
                    if self.quitAfterLaunch { NSApp.reply(toApplicationShouldTerminate: true) }
                    return
                }
                self.sessionURL = url
                self.launchComplete = true
                if self.quitAfterLaunch {
                    self.finishQuit(url)
                } else {
                    self.webView.load(URLRequest(url: url))
                }
            }
        }
    }

    nonisolated private static func validSessionURL(_ url: URL) -> Bool {
        url.scheme == "http" && url.host == "127.0.0.1" && url.port != nil &&
        url.user == nil && url.password == nil && url.path == "/" &&
        URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?
            .contains(where: { $0.name == "t" && !($0.value ?? "").isEmpty }) == true
    }

    private func isLocal(_ url: URL) -> Bool {
        guard let base = sessionURL else { return false }
        return url.scheme == base.scheme && url.host == base.host && url.port == base.port
    }

    private func openExternal(_ url: URL) {
        if ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
            NSWorkspace.shared.open(url)
        }
    }

    private func showError(_ text: String) {
        spinner.stopAnimation(nil)
        overlay.isHidden = false
        message.stringValue = text
        retryButton.isHidden = false
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        spinner.stopAnimation(nil)
        overlay.isHidden = true
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if (error as NSError).code != NSURLErrorCancelled {
            showError("无法加载本地控制台：\(error.localizedDescription)")
        }
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        showError("控制台渲染进程已退出，点击「重新启动」重新加载。")
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }
        if isLocal(url) {
            decisionHandler(.allow)
        } else {
            openExternal(url)
            decisionHandler(.cancel)
        }
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = navigationAction.request.url { openExternal(url) }
        return nil
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage text: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = text
        alert.addButton(withTitle: "确定")
        alert.addButton(withTitle: "取消")
        alert.beginSheetModal(for: window) { response in completionHandler(response == .alertFirstButtonReturn) }
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage text: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let alert = NSAlert()
        alert.messageText = text
        alert.beginSheetModal(for: window) { _ in completionHandler() }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame,
              let url = message.frameInfo.request.url, isLocal(url),
              let body = message.body as? [String: String] else { return }
        if body["action"] == "quit" { NSApp.terminate(nil) }
        if body["action"] == "copy", let text = body["text"], text.utf8.count <= 1_048_576 {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        NSApp.terminate(nil)
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        window.makeKeyAndOrderFront(nil)
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if terminating { return .terminateLater }
        terminating = true
        if launchProcess?.isRunning == true {
            // Do not leave a late-authorized root backend behind when the window closes.
            quitAfterLaunch = true
            message.stringValue = "正在等待系统授权结束，然后关闭后台。取消授权也可以退出。"
            return .terminateLater
        }
        guard let url = sessionURL else { return .terminateNow }
        overlay.isHidden = false
        spinner.startAnimation(nil)
        message.stringValue = "正在停止 DHCP 并恢复网口配置…"
        finishQuit(url)
        return .terminateLater
    }

    private func finishQuit(_ url: URL) {
        guard let token = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "t" })?.value else {
            NSApp.reply(toApplicationShouldTerminate: true)
            return
        }
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        config.timeoutIntervalForRequest = 45
        let http = URLSession(configuration: config)
        Task {
            defer { http.finishTasksAndInvalidate() }
            func post(_ path: String) async throws {
                let endpoint = URL(string: path, relativeTo: url)!.absoluteURL
                var request = URLRequest(url: endpoint)
                request.httpMethod = "POST"
                request.httpBody = Data("{}".utf8)
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.setValue(token, forHTTPHeaderField: "X-BMCD-Token")
                let (_, response) = try await http.data(for: request)
                if (response as? HTTPURLResponse)?.statusCode != 200 {
                    throw URLError(.badServerResponse)
                }
            }
            do {
                // /stop is synchronous: the NIC is restored before its response.
                try await post("/api/scan/stop")
                try await post("/api/scan/cleanup")
                try await post("/api/stop")
                try await post("/api/quit")
            } catch {
                // Quit is still attempted if a hung scan prevented orderly stopping.
                try? await post("/api/quit")
            }
            NSApp.reply(toApplicationShouldTerminate: true)
        }
    }

    @objc private func openLog() { NSWorkspace.shared.open(logURL) }

    @objc private func about() {
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "BMC DHCP",
            .applicationVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "",
            .credits: NSAttributedString(string: "给直连 BMC 分配临时地址，快速打开管理页面。")
        ])
    }

    @objc private func showHelp() {
        let alert = NSAlert()
        alert.messageText = "连接 BMC"
        alert.informativeText = "1. 用网线把 Mac 的以太网卡接到 BMC 管理口。\n2. 选择该网口，点击「启动服务」。\n3. 等待租约出现，点击「打开管理页」。\n\nBMC 需要启用 DHCP。已有静态 IP 时切换到「IP 探测」。使用独立管理链路。"
        alert.beginSheetModal(for: window)
    }
}

@main
struct BMCDHCP {
    @MainActor static func main() {
        let application = NSApplication.shared
        let desktop = Desktop()
        application.setActivationPolicy(.regular)
        application.delegate = desktop
        application.run()
    }
}
