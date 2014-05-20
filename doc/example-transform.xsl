<?xml version="1.0"?>
<!--
Simple xsl transformation of a log file. 

Example: Use "format xml" option in /etc/idsad.conf, then 
   
  idsaxmlheader < /var/log/idsa/idsa | xalanxslt -XSL ./example-transform.xsl

Where xalanxslt is the testXSLT of xalan found at http://xml.apache.org/
-->

<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'>
<xsl:template match="/">
<html>
<head>
<title>Example IDS/A Transformation</title>
</head>
<body>
<h1>Trivial Example of a Transformation applied to an IDS/A Log File</h1>
<table>
<tr>
<td>Time</td>
<td>Service[Pid]</td>
<td>Event.Scheme</td>
</tr>
<xsl:for-each select="log/event">
<tr>
<td><xsl:value-of select="time"/></td>
<td><b><xsl:value-of select="service"/></b>[<xsl:value-of select="pid"/>]</td>
<td><xsl:value-of select="name"/>.<xsl:value-of select="scheme"/></td>
</tr>
</xsl:for-each>
</table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
