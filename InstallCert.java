/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class InstallCert {

    public static void main(String[] args) throws Exception {
    String host;
    int port = 2000;
    char[] passphrase;

    if ((args.length == 1) || (args.length == 2)) {
        String[] c = args[0].split(":");
        host = c[0];
        port = (c.length == 1) ? 2000 : Integer.parseInt(c[1]);
        String p = (args.length == 1) ? "changeit" : args[1];
        passphrase = p.toCharArray();
    } else {
        System.out.println("Usage: java InstallCert <host> [passphrase]");
        return;
    }

    char SEP = File.separatorChar;
    File dir = new File(System.getProperty("java.home") + SEP + "lib" + SEP + "security");
    File file = new File(dir, "jssecacerts");
    if (file.isFile() == false) {
        file = new File(dir, "cacerts");
    }

    System.out.println("Loading KeyStore " + file + "...");
    InputStream in = new FileInputStream(file);
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    ks.load(in, passphrase);
    in.close();

    SSLContext context = SSLContext.getInstance("TLSv1.2");
    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ks);
    X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
    SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
    context.init(null, new TrustManager[] {tm}, null);
    SSLSocketFactory factory = context.getSocketFactory();

    System.out.println("Opening connection to " + host + ":" + port + "...");
    SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
    socket.setSoTimeout(10000);
    try {
        System.out.println("Starting SSL handshake...");
        socket.startHandshake();
        socket.close();
        System.out.println();
        System.out.println("certificate is already trusted");
        return;
    } catch (SSLException e) {
        //System.out.println();
        //e.printStackTrace(System.out);
    }

    X509Certificate[] chain = tm.chain;
    if (chain == null) {
        System.out.println("Could not obtain server certificate chain");
        return;
    }

    BufferedReader reader =
        new BufferedReader(new InputStreamReader(System.in));

    boolean found = false;
    int i;
    for (i = 0; i < chain.length; i++) {
        X509Certificate cert = chain[i];
        System.out.println("  Subject  " + cert.getSubjectDN());
        System.out.println("   Issuer  " + cert.getIssuerDN());
        System.out.println();

        Principal p = cert.getSubjectDN();
        if (p.getName().contains("vjdbc")) {
            found = true;
            break;
        }
    }

    if (! found) {
        System.out.println("no vjdbc certificate received");
        return;
    }

    File defaultfile = new File(dir, "jssecacerts");
    String outfilename = defaultfile.getAbsolutePath();
    File outfile = new File(outfilename);

    if (outfile.isFile() == true) {
        if (outfile.canWrite() == false) {
            System.out.println("no write access to file: " + outfilename);
            return;
        }
        System.out.println("backing up existing file");
        boolean result = outfile.renameTo(new File(outfilename + ".bak"));
    }
    else
    {
        if (dir.canWrite() == false) {
            System.out.println("no write access to dir: " + dir.getAbsolutePath());
            return;
        }
    }

    X509Certificate cert = chain[i];
    String alias = host + "-" + (i + 1);
    ks.setCertificateEntry(alias, cert);

    OutputStream out = new FileOutputStream(outfilename);
    ks.store(out, passphrase);
    out.close();

    System.out.println
        ("Added certificate to keystore '" + outfilename + "' using alias '" + alias + "'");
    }

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    private static String toHexString(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 3);
    for (int b : bytes) {
        b &= 0xff;
        sb.append(HEXDIGITS[b >> 4]);
        sb.append(HEXDIGITS[b & 15]);
        sb.append(' ');
    }
    return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {

    private final X509TrustManager tm;
    private X509Certificate[] chain;

    SavingTrustManager(X509TrustManager tm) {
        this.tm = tm;
    }

    public X509Certificate[] getAcceptedIssuers() {
        throw new UnsupportedOperationException();
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
        throw new UnsupportedOperationException();
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
        this.chain = chain;
        tm.checkServerTrusted(chain, authType);
    }
    }

}
