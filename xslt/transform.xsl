<?xml version="1.0" encoding="US-ASCII" ?>

<xsl:stylesheet version="1.0" 
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:db="http://www.database.dk"
                xmlns:oes="http://www.oes.dk">

  <xsl:template match="/">
    <oes:Output>
      <xsl:if test="string-length(/db:Input/db:DB_A/text()) > 0">
        <oes:OES_A>
          <xsl:value-of select="/db:Input/db:DB_A"/>
        </oes:OES_A>
      </xsl:if>
      
      <oes:OES_B>
      <xsl:value-of select="/db:Input/db:DB_B"/>
      </oes:OES_B>
      
      <oes:OES_C>
      <xsl:value-of select="/db:Input/db:DB_C"/>
      </oes:OES_C>
    </oes:Output>
  </xsl:template>
</xsl:stylesheet>
