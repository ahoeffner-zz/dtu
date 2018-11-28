package modssl;

import java.net.URL;
import javax.servlet.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Hashtable;
import java.io.OutputStream;
import javax.servlet.http.*;
import java.util.Enumeration;
import java.nio.charset.Charset;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import static modssl.SSLConfig.Config;


/**
 * <b>The SSL servlet will proxy for requests to "moderniserings styrelsen".<br>
 * Using the security model specified.</b>
 */
public class SSL extends HttpServlet
{
  private Hashtable<String,Hashtable<String,String>> config;
  private static final String CONTENT_TYPE = "text/xml; charset=UTF-8";
  
    
  public void init(ServletConfig config) throws ServletException
  {
    super.init(config);
    this.config = getConfig();
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
      Enumeration<String> hdrs = request.getHeaderNames();

      while(hdrs.hasMoreElements())
      {
        String name  = hdrs.nextElement();
        String value = request.getHeader(name);
        headers.add(new String[] {name,value});
      }

      in = request.getInputStream();
      out = response.getOutputStream();
            
      String query = request.getQueryString();
      if (query == null) query = "";
      if (query.length() > 1) query = "?"+query;
  
      String path = request.getPathInfo();
      if (path == null) path = "";
      
      String conf = "";
      int pos = path.indexOf("/",1);
      if (pos < 0) conf = path.substring(1);
      else conf = path.substring(1,pos);
      conf = conf.toLowerCase();
      
      System.out.println("configuration for "+conf+" = "+config.get(conf));

      if (config.get(conf) == null) conf="/";
      else path = path.substring(conf.length()+1);

      Hashtable<String,String> config = this.config.get(conf);
      String host = config.get("Host");
      
      if (path.length() > 1)
      {
        pos = path.indexOf("/");
        if (pos >= 0) path = path.substring(pos);
        path = "https://"+host+path;      
      }
      else path = "https://"+host;
            
      path = path + query;
      
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
  
      int read = 0;
      byte[] buf = new byte[4096];
  
      while(read >= 0)
      {
        read = in.read(buf);
        if (read > 0) buffer.write(buf,0,read);
      }

      byte[] input = buffer.toByteArray();
      
      try
      {
        FileOutputStream fout = new FileOutputStream("/tmp/messages.xml",true);
        fout.write(input);
        fout.write('\n');
        fout.close();
      }
      catch(Exception ex) {ex.printStackTrace();}

      if (config.get("Test") != null && config.get("Test").equals("true"))
      {
        System.err.println("request : "+path+", content : ");
        System.err.println(new String(input,Charset.forName("utf-8")));
      }

      response.setContentType(CONTENT_TYPE);
      byte[] output = invoke(config,headers,path,input);
      
      if (config.get("Test") != null && config.get("Test").equals("true"))
      {
        System.err.println("remote "+path+" returned : ");
        System.err.println(output);
      }
      
      try
      {
        FileOutputStream fout = new FileOutputStream("/tmp/modssl.xml",true);
        fout.write(output);
        fout.write('\n');
        fout.close();
      }
      catch(Exception ex) {ex.printStackTrace();}
      
      out.write(output);
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
      "     <![CDATA[" + result + "]]>\n" + 
      "     </faultstring>\n" + 
      "    </SOAP-ENV:Fault>\n" + 
      "  </SOAP-ENV:Body>\n" + 
      "</SOAP-ENV:Envelope>";
      
      try
      {
        FileOutputStream fout = new FileOutputStream("/tmp/modssl.xml",true);
        fout.write(fault.getBytes());
        fout.write('\n');
        fout.close();
      }
      catch(Exception ex) {ex.printStackTrace();}
      
      try{write(out,fault);}
      catch(Exception ex) {ex.printStackTrace();}
    }
  }
  

  private byte[] invoke(Hashtable<String,String> config, ArrayList<String[]> headers, String path, byte[] input) throws Exception
  {  
    URL url = new URL(path);
    System.out.println("invoke "+path);

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
    
    String key = "KeyStore";
    String file = config.get(key);

    key = "KeyStoreType";
    String type = config.get(key);

    key = "KeyStorePassword";
    String pass = config.get(key);

    Config prv = new Config(file,type,pass);

    key = "TrustStore";
    file = config.get(key);

    key = "TrustStoreType";
    type = config.get(key);

    key = "TrustStorePassword";
    pass = config.get(key);

    Config pub = new Config(file,type,pass);
    
    SSLConfig sslcfg = new SSLConfig(prv,pub);
    SSLContext sslctx = sslcfg.getSSLContext();
    SSLSocketFactory sslfac = sslctx.getSocketFactory();
        
    conn.setSSLSocketFactory(sslfac);
    conn.connect();

    OutputStream out = conn.getOutputStream();
    out.write(input);

    InputStream  in  = conn.getInputStream();
    InputStream  err = conn.getErrorStream();

    out.close();
    
    if (conn.getResponseCode() < 200 || conn.getResponseCode() >= 300)
      in = err;
      
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    int read = 0;
    byte[] buf = new byte[4096];

    while(read >= 0)
    {
      read = in.read(buf);
      if (read > 0) buffer.write(buf,0,read);
    }
    
    byte[] result = buffer.toByteArray();
    return(result);
  }
  
  
  private void write(OutputStream out, String message) throws Exception
  {
    out.write(message.getBytes("utf-8"));
  }
  
  
  private Hashtable<String,Hashtable<String,String>> getConfig()
  {
    Hashtable<String,Hashtable<String,String>> config = 
      new Hashtable<String,Hashtable<String,String>>();
    
    ServletContext context = getServletContext();
    Enumeration<String> parms = context.getInitParameterNames();
    
    while(parms.hasMoreElements())
    {
      String key = parms.nextElement();
      if (key.indexOf('.') > 0)
      {
        String conf = key.substring(0,key.indexOf('.'));
        conf = conf.toLowerCase();
        Hashtable<String,String> named = config.get(conf);
        if (named == null)
        {
          named = new Hashtable<String,String>();
          config.put(conf,named);
        }
        
        String entry = key.substring(key.indexOf('.')+1);
        named.put(entry,context.getInitParameter(key));
      }
      else
      {
        Hashtable<String,String> named = config.get("/");
        if (named == null)
        {
          named = new Hashtable<String,String>();
          config.put("/",named);
        }
        named.put(key,context.getInitParameter(key));
      }
    }
    
    return(config);
  }  
}
