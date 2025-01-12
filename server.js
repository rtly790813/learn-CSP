/** @format */

const express = require("express");
const app = express();
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

// 設定 view engine 為 ejs
app.set("view engine", "ejs");
// 設定 views 目錄
app.set("views", "./views");
// 提供靜態文件，比如 JS 和 CSS
app.use(express.static(path.join(__dirname, "public")));

// CSP 中間件 - 作為統一的設定
// app.use((req, res, next) => {
//     res.setHeader("Content-Security-Policy", "script-src 'self'");
//     next();
// });

// 1-csp-self
app.get("/csp-self", (req, res) => {
    // script-src 'self' 表示只允許來自本站的 script 執行，之後所有 inline sciprt 都會被阻擋
    res.header("Content-Security-Policy", "script-src 'self'");

    // 渲染 views/csp.ejs 頁面
    res.render("1-csp-self");
});

// 2-csp-domain
app.get("/csp-domain", (req, res) => {
    // 加上特定 Domain 之後，就可以載入該 Domain 資源
    res.header(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net; base-uri 'self'"
    );

    // 渲染 views/csp.ejs 頁面
    res.render("2-csp-domain");
});

// 3-csp-with-meta
app.get("/csp-with-meta", (req, res) => {
    // 與 html 中 meta 同時啟用 CSP，但指定不同 domain 進行測試
    res.header("Content-Security-Policy", "script-src 'self' https://cdn.jsdelivr.net");

    // 渲染 views/csp.ejs 頁面
    res.render("3-csp-with-meta");
});

// 4-csp-unsafe-inline
app.get("/csp-unsafe-inline", (req, res) => {
    // 增加了之後，inline-script 就可以開始執行了
    res.header(
        "Content-Security-Policy",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
    );

    // 渲染 views/csp.ejs 頁面
    res.render("4-csp-unsafe-inline");
});

// 5-csp-unsafe-eval 增加了之後就可以執行 eval()
app.get("/csp-unsafe-eval", (req, res) => {
    res.header(
        "Content-Security-Policy",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'  https://cdn.jsdelivr.net "
    );

    // 渲染 views/csp.ejs 頁面
    res.render("5-csp-unsafe-eval");
});

// 6 unsafe-hashes 可執行特定 script，無需搭配 unsafe-inline
app.get("/csp-unsafe-hashes", (req, res) => {
    // 定義內聯的 onclick 事件處理器
    const inlineEventHandler = "alert('clicked!')";

    // 使用 SHA-256 算法生成哈希值
    const hash = crypto.createHash("sha256").update(inlineEventHandler).digest("base64");
    const hashDirective = `'sha256-${hash}'`;

    res.header(
        "Content-Security-Policy",
        `script-src 'self' 'unsafe-hashes' ${hashDirective} https://cdn.jsdelivr.net `
    );

    // 渲染 views/csp.ejs 頁面
    res.render("6-csp-unsafe-hashes", { inlineEventHandler });
});

// 7 default-src 會將部分未設定的 Fetch directives 都依據程式碼關鍵字做限制，但不會覆蓋掉已設定的 Fetch directives
app.get("/csp-default-src", (req, res) => {
    res.header("Content-Security-Policy", "default-src 'self';");

    // 渲染 views/csp.ejs 頁面
    res.render("7-csp-default-src");
});

// 8 img-src with data: blob: ...etc
app.get("/csp-img-src", (req, res) => {
    res.header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src data:");

    // 渲染 views/csp.ejs 頁面
    res.render("8-csp-img-src");
});

// 9 nonce 首先在 server 端產出一個 crypto key
app.use((req, res, next) => {
    // 生成隨機 nonce
    res.locals.nonce = crypto.randomBytes(16).toString("base64");
    next();
});

app.get("/csp-nonce", (req, res) => {
    /**
     *  nonce 允許具有 nonce attr 的 inline-style 及 inline-script 執行
     *
     * 且 nonce 必須與 server 自動生成的值一致，當瀏覽器載入同時 CSP 針對標籤及 header response 進行驗證。
     * 相同的 nonce 才能夠被執行
     *
     * 根據 CSP 建議，nonce 應該是要隨機且不可重複使用的
     * You should use a cryptographically secure random token generator to generate a CSP nonce value. The random nonce value should only be used for a single HTTP request.
     * */
    res.header(
        "Content-Security-Policy",
        `script-src 'nonce-${res.locals.nonce}' ; style-src 'nonce-${res.locals.nonce}';`
    );

    // 渲染 views/csp.ejs 頁面
    res.render("9-csp-nonce", { nonce: res.locals.nonce });
});

// 10 hash 首先要依據程式碼中 inline 的內容，產出一個 sha 的雜湊
app.get("/csp-hash", (req, res) => {
    // 可以在 server 產，也可以透過第三方工具產出 https://emn178.github.io/online-tools/sha256.html

    // !! 在產出雜湊值的時候，程式碼要注意任何一個空白字元都需要被算進去，少一個都不行
    const scriptContent = `
            console.log(_.head([1, 2, 3]));
            const buttonElement = document.getElementById("test");
            buttonElement.addEventListener("click", () => {
                alert("from <script> addEventListener");
            });

            console.log("from eval", eval("2 + 2"));
        `;

    // 可以選擇使用 sha256 ,384,  512 ...etc 得到一個 binary 的值然後再轉乘 base64 (官方定義的)
    const hash = crypto.createHash("sha384").update(scriptContent).digest("base64");

    // 但不論是哪一種，前綴都一定要加上對應的 sha{256 | 384 | 512}，若加錯在畫面上就不會有任何效果
    const hashDirective = `'sha384-${hash}'`;

    // ! 建立一個 on event 的 hash >> alert('not working') 及 javascript:alert('Hello World!') 是不允許被執行的
    const hashForEvent = `'sha256-WrYOPZQoxRUyVl9Uka9QU6q5pGQQk2r12mziCjrn0SY='`;
    const hashForJs = `'sha256-ikRNjiOfVdOZZlCOyLWuyHLnVE6nW2bmJWjXtsTjGe0='`;

    // 第三方套件的話則是可以確認 CDN 本身是否有提供 intergrity，沒有的話就要自行生成
    // curl -O https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js
    // openssl dgst -sha384 -binary lodash.min.js | openssl base64 -A 此命令會輸出一串哈希值
    // 並將此值添加到script 的 integrity 屬性
    const hashForPlugin = `'sha384-H6KKS1H1WwuERMSm+54dYLzjg0fKqRK5ZRyASdbrI/lwrCc6bXEmtGYr5SwvP1pZ'`;

    res.header(
        "Content-Security-Policy",
        `script-src 'self' ${hashDirective} ${hashForEvent} ${hashForJs} ${hashForPlugin} ; default-src 'self'`
    );

    // 渲染 views/csp.ejs 頁面
    res.render("10-csp-hash");
});

// 11 strict dynamic
app.get("/csp-strict-dynamic", (req, res) => {
    res.header(
        "Content-Security-Policy",
        // 未加上 strict-dynamic
        // `script-src 'self' 'nonce-${res.locals.nonce}'; default-src 'self'; style-src 'unsafe-inline'`
        // 加上 strict-dynamic 但 img 未指定 domain
        `script-src 'self' https://cdn.jsdelivr.net/ 'nonce-${res.locals.nonce}'; default-src 'self' 'strict-dynamic'; style-src 'unsafe-inline';`
        // 加了 domain 之後 image 才能正常載入，表示 strict-dynamic 完全不影響 img 跟 css 動態靄入
        // `script-src 'self' 'nonce-${res.locals.nonce}'; default-src 'self' ; style-src 'unsafe-inline' https://cdn.jsdelivr.net/; img-src https://images.pexels.com/; `
    );

    // 渲染 views/csp.ejs 頁面
    res.render("11-csp-strict-dynamic", { nonce: res.locals.nonce });
});

// 12 CSP report
app.get("/csp-report", (req, res) => {
    // report-to 測試不出來 (X) Reorting-Endpoints 只能是 https
    res.header("Reporting-Endpoints", 'csp-endpoint="http://localhost:3000/csp-report-endpoint"');
    res.header(
        "Content-Security-Policy-Report-Only",
        `default-src 'self' 'strict-dynamic'; report-to csp-endpoint`
    );

    // 將 Content-Security-Policy >> 改為 Content-Security-Policy-Report-Only
    // 並且指定當條阻擋條件處發時要儲存的 log 紀錄位置 report-uri /csp-report-endpoint
    // 網址則是另外一個 API 裡面會去接收 csp-report，開發者可自行決定要加 log 寫入到哪邊，並且要儲存哪些資料
    res.header(
        "Content-Security-Policy-Report-Only",
        `default-src 'self' 'strict-dynamic'; report-uri /csp-report-endpoint`
    );

    // 渲染 views/csp.ejs 頁面
    res.render("12-csp-report", { nonce: res.locals.nonce });
});

// 添加處理 CSP 報告的端點
app.post(
    "/csp-report-endpoint",
    express.json({
        type: ["application/csp-report", "application/reports+json"],
    }),
    (req, res) => {
        console.log("req", req);
        const report = req.body;
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level: "error",
            message: "CSP 違規報告",
            report,
            userId: req.user ? req.user.id : null, // 假設有用戶身份驗證
            sessionId: req.session ? req.session.id : null, // 假設有會話管理
            ip: req.ip,
            userAgent: req.headers["user-agent"],
            requestPath: req.originalUrl,
        };

        // console.log(JSON.stringify(logEntry)); // 輸出結構化日誌到控制台

        // 將報告寫入文件
        fs.appendFile("csp-reports.log", JSON.stringify(logEntry) + "\n", (err) => {
            if (err) {
                console.error("寫入報告失敗:", err);
            }
        });

        res.status(204).end(); // 返回204狀態碼表示成功處理請求
    }
);

app.listen(3000, () => {
    console.log("Server is running on port 3000");
});
