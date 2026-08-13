package com.nginxscan.app.vuln

import com.nginxscan.app.data.CveHit

/**
 * Nginx 已知漏洞库（版本区间匹配，不执行实际 POC）
 */
object CveDatabase {

    private data class Cve(
        val id: String,
        val name: String,
        val description: String,
        val severity: String,
        val affected: List<VersionRange>,
    )

    private data class VersionRange(
        val min: String?,   // null = 不设下限
        val max: String?,   // null = 不设上限
        val minExclusive: Boolean = false,
        val maxExclusive: Boolean = false,
    )

    private val cves: List<Cve> = listOf(
        Cve(
            id = "CVE-2017-7529",
            name = "Nginx Range 过滤器整数溢出（信息泄露）",
            description = "Nginx 0.5.6 - 1.13.2 的 Range 过滤器存在整数溢出漏洞，可通过构造恶意 Range 请求头读取缓存文件中任意偏移量的数据，泄露敏感信息。",
            severity = "中危",
            affected = listOf(VersionRange("0.5.6", "1.13.2")),
        ),
        Cve(
            id = "CVE-2021-23017",
            name = "Nginx DNS Resolver 堆溢出",
            description = "Nginx 0.6.18 - 1.20.0 的 DNS 解析器存在堆缓冲区溢出漏洞，攻击者可通过特制 DNS 响应触发内存破坏，可能导致拒绝服务或任意代码执行。",
            severity = "高危",
            affected = listOf(VersionRange("0.6.18", "1.20.0")),
        ),
        Cve(
            id = "CVE-2019-9511",
            name = "HTTP/2 DATA DRIBBLE 拒绝服务",
            description = "Nginx 1.9.5 - 1.17.5 的 HTTP/2 实现存在资源消耗漏洞，攻击者可通过慢速发送 DATA 帧耗尽服务器内存/CPU，造成拒绝服务。",
            severity = "中危",
            affected = listOf(VersionRange("1.9.5", "1.17.5")),
        ),
        Cve(
            id = "CVE-2019-9513",
            name = "HTTP/2 资源循环拒绝服务",
            description = "Nginx 1.9.5 - 1.17.5 的 HTTP/2 实现存在资源循环漏洞，攻击者可利用空帧序列长期占用 worker 连接，造成拒绝服务。",
            severity = "中危",
            affected = listOf(VersionRange("1.9.5", "1.17.5")),
        ),
        Cve(
            id = "CVE-2022-41741",
            name = "Nginx ngx_http_mp4_module 内存越界写",
            description = "Nginx 1.23.2 的 mp4 模块存在堆内存越界写漏洞，配置了 mp4 模块且允许范围请求时，攻击者可造成 worker 崩溃，进一步可能导致代码执行。",
            severity = "高危",
            affected = listOf(VersionRange("1.23.2", "1.23.2")),
        ),
        Cve(
            id = "CVE-2022-41742",
            name = "Nginx ngx_http_mp4_module 内存泄漏",
            description = "Nginx 1.23.2 的 mp4 模块存在内存泄漏漏洞，攻击者可通过特制请求耗尽 worker 内存，造成拒绝服务。",
            severity = "中危",
            affected = listOf(VersionRange("1.23.2", "1.23.2")),
        ),
        Cve(
            id = "CVE-2024-7347",
            name = "Nginx ngx_http_mp4_module 段错误（DoS）",
            description = "Nginx 0.7.0 - 1.27.0 的 mp4 模块在开启且未禁用 range 请求时，特制 mp4 文件可触发断言失败导致 worker 段错误崩溃，造成拒绝服务。",
            severity = "中危",
            affected = listOf(VersionRange("0.7.0", "1.27.0")),
        ),
    )

    /**
     * 匹配某个版本号命中的漏洞列表
     */
    fun match(version: String): List<CveHit> {
        val v = normalize(version) ?: return emptyList()
        return cves
            .filter { cve -> cve.affected.any { range -> inRange(v, range) } }
            .map { cve ->
                CveHit(
                    cveId = cve.id,
                    name = cve.name,
                    description = cve.description,
                    affectedRange = cve.affected.joinToString(", ") { formatRange(it) },
                    severity = cve.severity,
                )
            }
    }

    private fun normalize(v: String): Triple<Int, Int, Int>? {
        val nums = v.trim().split(".").mapNotNull { it.toIntOrNull() }
        if (nums.isEmpty()) return null
        return Triple(
            nums.getOrElse(0) { 0 },
            nums.getOrElse(1) { 0 },
            nums.getOrElse(2) { 0 },
        )
    }

    private fun inRange(v: Triple<Int, Int, Int>, range: VersionRange): Boolean {
        val min = range.min?.let { normalize(it) }
        val max = range.max?.let { normalize(it) }
        if (min != null) {
            val cmp = compareTo(v, min)
            if (range.minExclusive && cmp <= 0) return false
            if (!range.minExclusive && cmp < 0) return false
        }
        if (max != null) {
            val cmp = compareTo(v, max)
            if (range.maxExclusive && cmp >= 0) return false
            if (!range.maxExclusive && cmp > 0) return false
        }
        return true
    }

    private fun compareTo(a: Triple<Int, Int, Int>, b: Triple<Int, Int, Int>): Int {
        val r = a.first.compareTo(b.first)
        if (r != 0) return r
        val r2 = a.second.compareTo(b.second)
        if (r2 != 0) return r2
        return a.third.compareTo(b.third)
    }

    private fun formatRange(range: VersionRange): String {
        val lo = if (range.min == null) "≤任何版本" else "≥ ${range.min}"
        val hi = if (range.max == null) "任何版本" else "≤ ${range.max}"
        return "$lo, $hi"
    }
}
