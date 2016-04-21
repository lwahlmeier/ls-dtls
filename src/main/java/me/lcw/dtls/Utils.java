package me.lcw.dtls;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Vector;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class Utils {

  public static SignatureAndHashAlgorithm findSignatureAndHashAlgorithm(Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, short signatureAlgorithm) {
    if (supportedSignatureAlgorithms != null) {
      for (SignatureAndHashAlgorithm sah: supportedSignatureAlgorithms) {
        if (sah.getSignature() == signatureAlgorithm) {
          return sah;
        }
      }
    }
    return null;
  }
  
  public static TlsSignerCredentials loadSignerCredentials(TlsContext context, String[] certResources, String keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
    Certificate certificate = loadCertificateChain(certResources);
    AsymmetricKeyParameter privateKey = loadPrivateKeyResource(keyResource);

    return new DefaultTlsSignerCredentials(context, certificate, privateKey, signatureAndHashAlgorithm);
  }
  
  public static Certificate loadCertificateChain(String[] resources) throws IOException {
    org.bouncycastle.asn1.x509.Certificate[] chain = new org.bouncycastle.asn1.x509.Certificate[resources.length];
    for (int i = 0; i < resources.length; ++i) {
      PemObject pem = loadPemFromFile(new File(resources[i]));
      if (pem.getType().endsWith("CERTIFICATE")) {
        chain[i] = org.bouncycastle.asn1.x509.Certificate.getInstance(pem.getContent());
      }
    }
    return new Certificate(chain);
  }
  
  public static AsymmetricKeyParameter loadPrivateKeyResource(String resource) throws IOException {
    PemObject pem = loadPemFromFile(new File(resource));
    if (pem.getType().endsWith("RSA PRIVATE KEY"))    {
      RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
      return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(),
          rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(),
          rsa.getExponent2(), rsa.getCoefficient());
    } else if (pem.getType().endsWith("PRIVATE KEY")) {
      return PrivateKeyFactory.createKey(pem.getContent());
    }
    throw new IllegalArgumentException("Invalid PrivateKey File:"+resource);
  }
  
  public static PemObject loadPemFromFile(File file) throws IOException {
    PemReader p = new PemReader(new InputStreamReader(new FileInputStream(file)));
    PemObject o = p.readPemObject();
    p.close();
    return o;
  }
}
