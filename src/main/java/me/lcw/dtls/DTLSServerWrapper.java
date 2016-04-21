package me.lcw.dtls;

import java.io.File;
import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsUtils;


public class DTLSServerWrapper extends DefaultTlsServer {

  private final File keyPath;
  private final File certPath;

  public DTLSServerWrapper(String key, String cert) {
    keyPath = new File(key);
    certPath = new File(cert);
  }

  @Override
  public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
    System.out.println("DTLS alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
    if (message != null) {
      System.out.println(message);
    }
    if (cause != null) {
      cause.printStackTrace();
    }
  }

  @Override
  public void notifyAlertReceived(short alertLevel, short alertDescription) {
    System.out.println("DTLS alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
  }

  public CertificateRequest getCertificateRequest() throws IOException {
    short[] certificateTypes = new short[]{ 
        ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign 
    };

    Vector serverSigAlgs = null;
    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion)) {
      serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms();
    }

    Vector certificateAuthorities = new Vector();

    return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
  }

  public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCertificate) throws IOException {

  }

  protected ProtocolVersion getMaximumVersion() {
    return ProtocolVersion.DTLSv12;
  }

  protected ProtocolVersion getMinimumVersion() {
    return ProtocolVersion.DTLSv10;
  }

  protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
    return TlsTestUtils.loadEncryptionCredentials(context, new String[]{certPath.getAbsolutePath()}, keyPath.getAbsolutePath());
  }

  protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
    return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.rsa, certPath.getAbsolutePath(), keyPath.getAbsolutePath());
  }
}
