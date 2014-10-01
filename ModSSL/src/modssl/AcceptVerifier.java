package modssl;

import javax.net.ssl.SSLSession;
import javax.net.ssl.HostnameVerifier;
//import weblogic.security.SSL.HostnameVerifier;


class AcceptVerifier implements HostnameVerifier
{
  protected AcceptVerifier()
  {
  }


  public boolean verify(String host, SSLSession session)
  {
    return(true);
  }
}
