package org.example;

import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class PemToPfx {
    // Pem zu PFX
    // nimmt eine PEM-Datei mit allen Zertifikaten und baut diese wieder im Keystore zusammen
    public static Path convertPemToPfx(String pemFile, String privateKeyPassword) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Laden des privaten Schlüssels
        PrivateKey privateKey = loadPrivateKey(pemFile, privateKeyPassword);

        // Entfernen des privaten Schlüssels aus der PEM-Datei und Speichern der verbleibenden Zertifikate in einer temporären Datei
        String tempPemFile = createTemporaryPemWithoutPrivateKey(pemFile);

        // Laden der Zertifikate aus der temporären PEM-Datei
        List<Certificate> certificates = loadCertificatesFromPEM(tempPemFile);

        char[] privateKeyPasswordCharArray = privateKeyPassword.toCharArray();

        // Erzeugen des Keystores
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        // Hinzufügen der Zertifikate und des privaten Schlüssels zum Keystore
        for (int i = 0; i < certificates.size(); i++) {
            keyStore.setCertificateEntry("certificate" + i, certificates.get(i));
        }
        keyStore.setKeyEntry("privateKey", privateKey, privateKeyPasswordCharArray, certificates.toArray(new Certificate[0]));

        Path tempPfxFilePath = Files.createTempFile("temp_keystore", ".pfx");

        // Speichern des Keystores als PFX-Datei
        try (FileOutputStream fos =  new FileOutputStream(tempPfxFilePath.toFile())) {
            keyStore.store(fos, privateKeyPasswordCharArray);
        }

        System.out.println("PFX-Datei erfolgreich erstellt: " + tempPfxFilePath);
        return tempPfxFilePath;
    }

    private static String createTemporaryPemWithoutPrivateKey(String pemFile) throws IOException {
        String tempPemFile = "temp.pem";
        try (BufferedReader br = new BufferedReader(new FileReader(pemFile));
             BufferedWriter bw = new BufferedWriter(new FileWriter(tempPemFile))) {
            String line;
            boolean foundPrivateKey = false;
            while ((line = br.readLine()) != null) {
                if (line.contains("-----BEGIN PRIVATE KEY-----")) {
                    foundPrivateKey = true;
                    continue;
                }
                if (line.contains("-----END PRIVATE KEY-----")) {
                    foundPrivateKey = false;
                    continue;
                }
                if (!foundPrivateKey) {
                    bw.write(line);
                    bw.newLine();
                }
            }
        }
        return tempPemFile;
    }

    private static List<Certificate> loadCertificatesFromPEM(String tempPemFile) throws IOException, CertificateException {
        List<Certificate> certificates = new ArrayList<>();
        FileInputStream fis = new FileInputStream(tempPemFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs = cf.generateCertificates(fis);
        for (Certificate cert : certs) {
            if (!certificates.contains(cert)) {
                certificates.add(cert);
            }
        }
        fis.close();
        return certificates;
    }

    private static PrivateKey loadPrivateKey(String pemFile, String privateKeyPassword) throws Exception {
        StringBuilder pkcs8Lines = new StringBuilder();
        boolean foundKey = false;
        try (BufferedReader reader = new BufferedReader(new FileReader(pemFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("-----BEGIN PRIVATE KEY-----")) {
                    foundKey = true;
                }
                if (foundKey) {
                    pkcs8Lines.append(line).append("\n");
                }
                if (line.contains("-----END PRIVATE KEY-----")) {
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        byte[] pkcs8EncodedBytes = Base64.decode(pkcs8Pem);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedBytes));
    }
}