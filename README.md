# Nginx 资产扫描

Android 应用：FoFa 拉取资产 → 并发探测识别 Nginx 版本 → CVE 漏洞版本匹配。

## 功能
- FoFa API 拉取资产（FOFACLI_FOFA_KEY 单 key 模式）
- 并发 HTTP 探测，识别 Nginx 版本号（Server 头 + 错误页指纹，含版本隐藏检测）
- 内置 7 个 Nginx CVE 版本区间匹配
- 一键导出 CSV

## 构建
```bash
./gradlew assembleDebug
```
APK 输出：`app/build/outputs/apk/debug/app-debug.apk`

> 注意：本项目仅限授权目标的安全评估使用。
