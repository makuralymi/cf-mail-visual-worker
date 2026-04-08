import appStyles from "./frontend/appStyles.css";
import appMarkup from "./frontend/appMarkup.html";
import appClientScript from "./frontend/appClient.browser.js";

// 统一拼装 HTML，Worker 仅负责返回页面
export function renderAppHtml() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cloudflare Mail Visual Worker</title>
  <style>
${appStyles}
  </style>
</head>
<body>
${appMarkup}
  <script>
${appClientScript}
  </script>
</body>
</html>`;
}
