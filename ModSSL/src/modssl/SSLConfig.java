package modssl;

import java.security.Key;
import java.util.Enumeration;
import java.security.KeyStore;
import java.io.FileInputStream;
import javax.net.ssl.SSLContext;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import javax.net.ssl.KeyManagerFactory;
import static java.security.KeyStore.*;
import java.security.SecureRandom;

import javax.net.ssl.TrustManagerFactory;
import java.security.UnrecoverableKeyException;


public class SSLConfig
{
  private final SSLContext sslctx;
  
  
  public static PrivateKey getKey(Config conf) throws Exception
  {
    FileInputStream stream = new FileInputStream(conf.getFile());
    KeyStore store = KeyStore.getInstance(conf.getType());
    store.load(stream,conf.getPassPhrase());
    Key prvkey = store.getKey(conf.getAlias(),conf.getPassPhrase());
    return((PrivateKey) prvkey);
  }
  
  
  public static Certificate getCert(Config conf) throws Exception
  {
    FileInputStream stream = new FileInputStream(conf.getFile());
    KeyStore store = KeyStore.getInstance(conf.getType());
    store.load(stream,conf.getPassPhrase());
    Certificate cert = store.getCertificate(conf.getAlias());
    return(cert);
  }
  
  
  public SSLConfig(Config prv, Config pub) throws Exception
  {
    FileInputStream stream = new FileInputStream(prv.getFile());
    KeyStore prvstore = KeyStore.getInstance(prv.getType());
    prvstore.load(stream,prv.getPassPhrase());
    
    String alias = null;

    if (prv.getAliases().length == 1)
    {
      alias = prv.getAlias();
    }
    else
    {
      Enumeration<String> aliases = prvstore.aliases();
      alias = aliases.nextElement();
    }
        
    PrivateKey prvkey = (PrivateKey) prvstore.getKey(alias,prv.getPassPhrase());
    Certificate[] chain = prvstore.getCertificateChain(alias);
    
    stream = new FileInputStream(pub.getFile());
    KeyStore pubstore = KeyStore.getInstance(pub.getType());
    pubstore.load(stream,pub.getPassPhrase());
    
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    
    prvstore = KeyStore.getInstance("jks");
    prvstore.load(null,prv.getPassPhrase());
    prvstore.setKeyEntry("private",prvkey,prv.getPassPhrase(),chain);

    tmf.init(pubstore);
    kmf.init(prvstore,prv.getPassPhrase());
    
    sslctx = SSLContext.getInstance("TLS");
    sslctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());  
  }
  
  
  public SSLConfig(Config usr) throws Exception
  {
    FileInputStream stream = new FileInputStream(usr.getFile());
    KeyStore prvstore = KeyStore.getInstance(usr.getType());
    prvstore.load(stream,usr.getPassPhrase());
    
    String pubalias = null;
    String prvalias = null;

    Enumeration<String> aliases = prvstore.aliases();
    PasswordProtection protection = new PasswordProtection(usr.getPassPhrase());

    while(aliases.hasMoreElements())
    {
      String alias = aliases.nextElement();
      Entry entry = null;
      
      try
      {
        entry = prvstore.getEntry(alias,null);
      }
      catch(UnrecoverableKeyException e)
      {
        entry = prvstore.getEntry(alias,protection);
      }
      
      if (entry instanceof PrivateKeyEntry) prvalias = alias;
      else                                  pubalias = alias;
    }

    Certificate trust = prvstore.getCertificate(pubalias);
        
    PrivateKey prvkey = (PrivateKey) prvstore.getKey(prvalias,usr.getPassPhrase());
    Certificate[] chain = prvstore.getCertificateChain(prvalias);
    
    KeyStore pubstore = KeyStore.getInstance("jks");
    pubstore.load(null,usr.getPassPhrase());
    
    prvstore = KeyStore.getInstance("jks");
    prvstore.load(null,usr.getPassPhrase());
    
    pubstore.setCertificateEntry(pubalias,trust);
    prvstore.setKeyEntry("private",prvkey,usr.getPassPhrase(),chain);
    
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

    tmf.init(pubstore);
    kmf.init(prvstore,usr.getPassPhrase());
    
    sslctx = SSLContext.getInstance("TLS");
    sslctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());  
  }
  
  
  public SSLConfig(Config usr, String prvalias, String pubalias) throws Exception
  {
    FileInputStream stream = new FileInputStream(usr.getFile());
    KeyStore prvstore = KeyStore.getInstance(usr.getType());
    prvstore.load(stream,usr.getPassPhrase());
        
    Certificate trust = prvstore.getCertificate(pubalias);
        
    PrivateKey prvkey = (PrivateKey) prvstore.getKey(prvalias,usr.getPassPhrase());
    Certificate[] chain = prvstore.getCertificateChain(prvalias);
    
    KeyStore pubstore = KeyStore.getInstance("jks");
    pubstore.load(null,usr.getPassPhrase());
    
    prvstore = KeyStore.getInstance("jks");
    prvstore.load(null,usr.getPassPhrase());
    
    pubstore.setCertificateEntry(pubalias,trust);
    prvstore.setKeyEntry("private",prvkey,usr.getPassPhrase(),chain);
    
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

    tmf.init(pubstore);
    kmf.init(prvstore,usr.getPassPhrase());
    
    sslctx = SSLContext.getInstance("TLS");
    sslctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());  
  }
  
  
  public SSLContext getSSLContext()
  {
    return(sslctx);
  }
  
  
  public static class Config
  {
    private final String file;
    private final String type;
    private final String pass;
    private final String[] aliases;
    
    public Config(String file, String type, String pass, String... alias)
    {
      this.file = file;
      this.type = type;
      this.pass = pass;
      this.aliases = alias;
    }

    public String getFile()
    {
      return(file);
    }

    public String getType()
    {
      return(type);
    }

    public String getAlias()
    {
      return(aliases[0]);
    }

    public String[] getAliases()
    {
      return(aliases);
    }

    public char[] getPassPhrase()
    {
      return(pass.toCharArray());
    }
    
    
    public String toString()
    {
      if (aliases == null || aliases.length == 0) 
        return(file);
      return(file+" "+aliases[0]);
    }
  }
}
