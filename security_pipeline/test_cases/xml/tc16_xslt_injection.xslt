<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt">

    <xsl:param name="userParam"/>

    <!-- TC-XI-01: POSITIVE/CRITICAL — file read via document() -->
    <xsl:template match="file-read">
        <xsl:value-of select="document('file:///etc/passwd')"/>
    </xsl:template>

    <!-- TC-XI-02: POSITIVE/CRITICAL — PHP code execution -->
    <xsl:template match="rce">
        <xsl:value-of select="php:function('system', 'id')"/>
    </xsl:template>

    <!-- TC-XI-03: POSITIVE/MEDIUM — information disclosure -->
    <xsl:template match="info">
        <xsl:value-of select="system-property('xsl:vendor')"/>
        <xsl:value-of select="system-property('xsl:version')"/>
    </xsl:template>

    <!-- TC-XI-04: POSITIVE/HIGH — SSRF via user-controlled param -->
    <xsl:template match="ssrf">
        <xsl:value-of select="document($userParam)"/>
    </xsl:template>

    <!-- TC-XI-05: POSITIVE/HIGH — raw HTML output (XSS risk) -->
    <xsl:template match="xss">
        <xsl:value-of select="user-content" disable-output-escaping="yes"/>
    </xsl:template>

    <!-- TC-XI-06: POSITIVE/CRITICAL — Microsoft XSLT script execution -->
    <msxsl:script language="JScript">
        function exploit() { return new ActiveXObject("WScript.Shell").Run("calc"); }
    </msxsl:script>

    <!-- TC-XI-07: NEGATIVE — safe static value-of -->
    <xsl:template match="safe1">
        <xsl:value-of select="title"/>
    </xsl:template>

    <!-- TC-XI-08: NEGATIVE — standard template match -->
    <xsl:template match="/">
        <html><body>
            <xsl:apply-templates/>
        </body></html>
    </xsl:template>

</xsl:stylesheet>
