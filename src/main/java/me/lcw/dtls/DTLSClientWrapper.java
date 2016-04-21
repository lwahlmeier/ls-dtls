package me.lcw.dtls;

import java.io.File;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.MaxFragmentLength;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


public class DTLSClientWrapper extends DefaultTlsClient {
  protected TlsSession session;
  private final File keyPath;
  private final File certPath;

  public DTLSClientWrapper() {
    this(null, null, null);
  }

  public DTLSClientWrapper(String key, String cert) {
    this(null, key, cert);
  }

  public DTLSClientWrapper(TlsSession session, String key, String cert) {
    this.session = session;
    if(key != null && cert != null) {
      keyPath = new File(key);
      certPath = new File(cert);
    } else {
      keyPath = null;
      certPath = null;
    }
  }

  public TlsSession getSessionToResume() {
    return this.session;
  }

  public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
    System.out.println("DTLS alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
    if (message != null) {
      System.out.println(message);
    }
    if (cause != null) {
      cause.printStackTrace();
    }
  }

  public void notifyAlertReceived(short alertLevel, short alertDescription) {
    System.out.println("DTLS alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
  }

  public ProtocolVersion getClientVersion() {
    return ProtocolVersion.DTLSv12;
  }

  public ProtocolVersion getMinimumVersion() {
    return ProtocolVersion.DTLSv10;
  }

  public Hashtable getClientExtensions() throws IOException {
    Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
    TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
    TlsExtensionsUtils.addExtendedMasterSecretExtension(clientExtensions);
    TlsExtensionsUtils.addMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_10);
    TlsExtensionsUtils.addTruncatedHMacExtension(clientExtensions);
    return clientExtensions;
  }

  public TlsAuthentication getAuthentication() throws IOException {
    return new TlsAuthentication() {
      public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException {

      }

      public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
        short[] certificateTypes = certificateRequest.getCertificateTypes();
        if (keyPath == null || certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign)) {
          return null;
        } else {
          SignatureAndHashAlgorithm sha = Utils.findSignatureAndHashAlgorithm((Vector<SignatureAndHashAlgorithm>)certificateRequest.getSupportedSignatureAlgorithms(), SignatureAlgorithm.rsa);
          return Utils.loadSignerCredentials(context, new String[] {certPath.getAbsolutePath()}, keyPath.getAbsolutePath(), sha);
        }
      }
    };
  }

  public void notifyHandshakeComplete() throws IOException {
    super.notifyHandshakeComplete();

    TlsSession newSession = context.getResumableSession();
    if (newSession != null) {
      byte[] newSessionID = newSession.getSessionID();
      String hex = Hex.toHexString(newSessionID);

      if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID)) {
        System.out.println("Resumed session: " + hex);
      } else {
        System.out.println("Established session: " + hex);
      }

      this.session = newSession;
    }
  }
}
