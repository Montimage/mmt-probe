<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- MMT_Security Copyright (C) 2013  Montimage
     Description: XSL file for viewing results from MMT_Security
-->

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <html>
  <head>
<title>MMT-Security Results</title>
<link href="results.css" rel="stylesheet" type="text/css" />
</head>

  <body>

<h2>Execution Results Report</h2>
    <table id="one-column-emphasis" width="90%">
      <colgroup>
    	<col class="oce-first" />
      </colgroup>
      <tr>
        <td width="15%"><strong>Project Name:</strong></td>
        <td width="85%">Advanced monitoring of network packets for security checking using the MMT tool</td>
      </tr>
      <tr>
        <td><strong>Project Description:</strong></td>
        <td>Montimage Monitoring Tool (MMT) is a functional and security analysis tool that verifies the network traffic trace of an application or protocol against a set of properties called MMT-Security properties. MMT can be
executed against a recorded packet trace file or live on a network interface for real time analysis.</td>
      </tr>
      <!--tr>
        <td><strong>Demonstrator parameters:</strong></td>
        <td>6 security rules were specified and checked using MMT. The results are provided in the next sections</td>
      </tr-->
    </table>
    <hr />

 <xsl:if test="results/summary/sp/description!='none'">
  <h3>Security rules summary results</h3>
  <table id="box-table-a" width="90%" >
    <tr>
      <th>Id</th>
      <th>Description</th>
	  <th align='center'><img src='images/OKShield-icon.png' width='32' height='32' alt='Respected' /></th>
	  <th align='center'><img src='images/ErrorCircle-icon.png' width='32' height='32' alt='Not respected' /></th>
    </tr>
    <xsl:for-each select="results/summary/sp">
    <tr>
      <td><xsl:value-of select="id"/></td>
      <td width="90%"><xsl:value-of select="description"/></td>
	  <td align="center"><xsl:value-of select="respected"/></td>
      <td align="center"><xsl:value-of select="violated"/></td>
    </tr>
    </xsl:for-each>
  </table>
 </xsl:if>
 <xsl:if test="results/summary/spb/description!='none'">
 <h3>Attack summary results</h3>
 <table id="box-table-a" width="90%" >
    <tr>
      <th>Id</th>
      <th>Description</th>
	  <th align='center'><img src='images/Attack-icon.png' width='32' height='32' alt='Detected' /></th>
	  <th align='center'><img src='images/No_attack-icon.png' width='32' height='32' alt='Not detected' /></th>
    </tr>
    <xsl:for-each select="results/summary/spb">
    <tr>
      <td><xsl:value-of select="id"/></td>
      <td width="90%"><xsl:value-of select="description"/></td>
	  <td align="center"><xsl:value-of select="detected"/></td>
      <td align="center"><xsl:value-of select="not_detected"/></td>
    </tr>
    </xsl:for-each>
  </table>
 </xsl:if>
      <hr />

  
  <h3>Results Details</h3>
  <table id="box-table-a" width="90%" >
    <tr>
      <th>Pid</th>
	  <th>Verdict</th>
      <th colspan="3">Property description</th>
    </tr>
    <xsl:for-each select="results/detail/occurence">
    <tr>
	  <xsl:variable name="nbev"><xsl:value-of select="nbevents"/></xsl:variable>
      <td ><xsl:value-of select="pid"/></td>
       <td >
	  <xsl:choose>
	  <xsl:when test="verdict='respected'">
	    <img src='images/OKShield-icon.png' width='32' height='32' alt='Respected' />
	  </xsl:when>
	  <xsl:when test="verdict='not_respected'">
	    <img src='images/ErrorCircle-icon.png' width='32' height='32' alt='Not respected' />
	  </xsl:when>
	  <xsl:when test="verdict='detected'">
	    <img src='images/Attack-icon.png' width='32' height='32' alt='Detected' />
	  </xsl:when>
	  <xsl:when test="verdict='not_detected'">
	    <img src='images/No_attack-icon.png' width='32' height='32' alt='Not_detected' />
	  </xsl:when>
	  <xsl:otherwise>
	    <img src='images/Other-icon.png' width='32' height='32' alt='Failed' />
          </xsl:otherwise>
	  </xsl:choose>
	  </td>
	  <td colspan="3"><xsl:value-of select="description"/></td>
	</tr>
	
	<xsl:for-each select="event">
	<tr>
	  <td></td>
	  <!--td>Event: <xsl:value-of select="id"/></td-->
	  <td></td>
	  <td><xsl:value-of select="description"/></td>
	</tr>
<xsl:for-each select="attribute">
	  <tr>
	    <td></td>
	    <td></td>
	    <td><xsl:value-of select="attribute_value"/></td>
	  </tr>
</xsl:for-each>
	</xsl:for-each>
    </xsl:for-each>
  </table>
  	
 
  
  </body>
  </html>
</xsl:template>

</xsl:stylesheet>
