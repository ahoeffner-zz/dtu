package modssl;

import java.net.URL;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Enumeration;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
//import weblogic.security.SSL.HostnameVerifier;
//import weblogic.net.http.HttpsURLConnection;


/**
 * <b>The SSL servlet will proxy for requests to "moderniserings styrelsen".<br>
 * Using the security model specified.</b>
 */
public class SSL extends HttpServlet
{
  private static final String CONTENT_TYPE = "text/xml; charset=UTF-8";
  
  
  public void init(ServletConfig config) throws ServletException
  {
    super.init(config);
  }
  

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
  {
    doPost(request,response);
  }


  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
  {
    modssl(request,response);
  }
  

  private void modssl(HttpServletRequest request, HttpServletResponse response)
  {    
    InputStream in = null;
    OutputStream out = null;
    ArrayList<String[]> headers = new ArrayList<String[]>();

    try
    {
      Hashtable<String,String> config = getConfig();
      
      Enumeration hdrs = request.getHeaderNames();
      while(hdrs.hasMoreElements())
      {
        String name = (String) hdrs.nextElement();
        String value = request.getHeader(name);
        headers.add(new String[] {name,value});
      }

      in = request.getInputStream();
      out = response.getOutputStream();
      
      ServletContext context = getServletContext();
      String host = context.getInitParameter("Host");
      
      String query = request.getQueryString();
      if (query == null) query = "";
      if (query.length() > 1) query = "?"+query;
  
      String path = request.getPathInfo();
      if (path == null) path = "";
      
      if (path.length() > 1)
      {
        int pos = path.indexOf("/");
        if (pos >= 0) path = path.substring(pos);
        path = "https://"+host+path;      
      }
      else path = "https://"+host;
      
      path = path + query;
      
      StringBuffer buffer = new StringBuffer();
  
      int read = 0;
      byte[] buf = new byte[4096];
  
      while(read >= 0)
      {
        read = in.read(buf);
        if (read > 0) buffer.append(new String(buf,0,read));
      }

      String input = buffer.toString();

      if (config.get("Test").equals("true"))
      {
        System.err.println("request : "+path+", content : ");
        System.err.println(input);
      }

      response.setContentType(CONTENT_TYPE);      
      String output = invoke(config,headers,path,input);
      
      if (config.get("Test").equals("true"))
      {
        System.err.println("remote "+path+" returned : ");
        System.err.println(output);
      }
      
      write(out,output);
  
      out.close();
      in.close();
    }
    catch(Exception e) 
    {
      ByteArrayOutputStream err = new ByteArrayOutputStream();
      e.printStackTrace(new PrintStream(err));
      String result = new String(err.toByteArray());
      
      String fault = "<SOAP-ENV:Envelope\n" + 
      "  xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"\n" + 
      "  xmlns:xsi=\"http://www.w3.org/1999/XMLSchema-instance\"\n" + 
      "  xmlns:xsd=\"http://www.w3.org/1999/XMLSchema\">\n" + 
      "   <SOAP-ENV:Body>\n" + 
      "    <SOAP-ENV:Fault>\n" + 
      "     <faultcode xsi:type=\"xsd:string\">SOAP-ENV:Client</faultcode>\n" + 
      "     <faultstring xsi:type=\"xsd:string\">\n" + 
              result + "\n" + 
      "     </faultstring>\n" + 
      "    </SOAP-ENV:Fault>\n" + 
      "  </SOAP-ENV:Body>\n" + 
      "</SOAP-ENV:Envelope>";
      
      try{write(out,fault);}
      catch(Exception ex) {e.printStackTrace();}
    }
  }
  

  private String invoke(Hashtable<String,String> config, ArrayList<String[]> headers, String path, String input) throws Exception
  {  
    URL url = new URL(path);

    System.setProperty("javax.net.ssl.keyStore",config.get("KeyStore"));
    System.setProperty("javax.net.ssl.keyStoreType",config.get("KeyStoreType"));
    System.setProperty("javax.net.ssl.keyStorePassword",config.get("KeyStorePassword"));
    System.setProperty("javax.net.ssl.trustStore",config.get("TrustStore"));
    System.setProperty("javax.net.ssl.trustStoreType",config.get("TrustStoreType"));
    System.setProperty("javax.net.ssl.trustStorePassword",config.get("TrustStorePassword"));
    if (config.get("Debug").equals("true")) System.setProperty("javax.net.debug","SSL");
    else System.clearProperty("javax.net.debug");
    
    HostnameVerifier verifier = new AcceptVerifier();
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    conn.setHostnameVerifier(verifier);
    
    conn.setRequestMethod("POST");
    
    for (int i = 0; i < headers.size(); i++)
    {
      String[] nvp = headers.get(i);
      conn.setRequestProperty(nvp[0],nvp[1]);
    }

    headers.clear();    

    conn.setDoInput(true);
    conn.setDoOutput(true);

    OutputStream out = conn.getOutputStream();
    write(out,input);

    InputStream  in  = conn.getInputStream();
    InputStream  err = conn.getErrorStream();

    out.close();
    
    if (conn.getResponseCode() < 200 || conn.getResponseCode() >= 300)
      in = err;
      
    StringBuffer buffer = new StringBuffer();

    int read = 0;
    byte[] buf = new byte[4096];

    while(read >= 0)
    {
      read = in.read(buf);
      if (read > 0) buffer.append(new String(buf,0,read));
    }
    
    String result = buffer.toString();
    return(result);
  }
  
  
  private void write(OutputStream out, String message) throws Exception
  {
    out.write(message.getBytes("utf-8"));
  }
  
  
  private Hashtable<String,String> getConfig()
  {
    Hashtable<String,String> config = 
      new Hashtable<String,String>();
    
    ServletContext context = getServletContext();
    
    String key = "Host";
    String value = context.getInitParameter(key);
    config.put(key,value);
    
    key = "KeyStore";
    value = context.getInitParameter(key);
    config.put(key,value);
    
    key = "KeyStoreType";
    value = context.getInitParameter(key);
    config.put(key,value);
    
    key = "KeyStorePassword";
    value = context.getInitParameter(key);
    config.put(key,value);    
    
    key = "TrustStore";
    value = context.getInitParameter(key);
    config.put(key,value);
    
    key = "TrustStoreType";
    value = context.getInitParameter(key);
    config.put(key,value);
    
    key = "TrustStorePassword";
    value = context.getInitParameter(key);
    config.put(key,value);    
    
    key = "Test";
    value = context.getInitParameter(key);
    config.put(key,value.toLowerCase());    
    
    key = "Debug";
    value = context.getInitParameter(key);
    config.put(key,value.toLowerCase());
    
    return(config);
  }
}
