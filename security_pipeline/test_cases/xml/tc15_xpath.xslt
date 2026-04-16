<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

    <xsl:param name="userParam"/>
    <xsl:param name="searchId"/>

    <!-- TC-XP-01: POSITIVE — variable in XPath predicate -->
    <xsl:template match="/">
        <xsl:value-of select="//user[$userParam]"/>
    </xsl:template>

    <!-- TC-XP-02: POSITIVE — concat in XPath -->
    <xsl:template match="search">
        <xsl:value-of select="concat('//items/', $searchId)"/>
    </xsl:template>

    <!-- TC-XP-03: POSITIVE — xpath attribute with variable -->
    <config xpath="//item[@id=$id]"/>

    <!-- TC-XP-04: NEGATIVE — static XPath, no variables -->
    <xsl:template match="books">
        <xsl:value-of select="//book/title"/>
    </xsl:template>

    <!-- TC-XP-05: NEGATIVE — current node, harmless -->
    <xsl:template match="item">
        <xsl:value-of select="."/>
    </xsl:template>

</xsl:stylesheet>
