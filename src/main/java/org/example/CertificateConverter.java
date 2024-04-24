package org.example;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Predicate;

import static org.example.PemToPfx.convertPemToPfx;

public class CertificateConverter {
    private static X509Certificate rootCertificate;
    private static X509Certificate intermediate02Certificate;
    private static X509Certificate intermediate01Certificate;
    private static X509Certificate CACertificate;
    private static Certificate[] chain;
    private static PrivateKey privateKey;
    private static  String keystorePassword;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Bitte geben Sie den Dateipfad zum Zertifiat ein:");
        String filePath = scanner.nextLine();
        try {
            Path file = Paths.get(filePath);
            if (!Files.exists(file)) {
                System.out.println("Die angegebene Datei existiert nicht. Das Programm wird beendet.");
                return;
            }

            String fileType = getFileType(file);
            if ("pem".equals(fileType)) {
                System.out.println("Geben Sie das Keystore-Passwort ein:");
                String keystorePassword = scanner.nextLine();

                // Konvertierung der PEM-Datei in eine temporäre PFX-Datei und Rückgabe des Dateipfads
                String tempPfxFile = String.valueOf(convertPemToPfx(filePath, keystorePassword));

                // Zum Beispiel: PFX-Datei an eine andere Methode übergeben oder direkt verwenden
                file = Path.of(tempPfxFile);

                fileType = "pfx";
            }

            System.out.println("Geben sie das Zielformat ein (ClearPass/Innovaphone)");
            String chainChoice = scanner.nextLine();

            if ("ClearPass".equalsIgnoreCase(chainChoice) || "Innovaphone".equalsIgnoreCase(chainChoice)) {

                boolean passwordCorrect = false;
                while (!passwordCorrect) {
                    System.out.println("Geben Sie das Keystore-Passwort ein:");
                    keystorePassword = scanner.nextLine();

                    if ("pfx".equals(fileType)) {
                        try {
                            setupKeyStore(file, keystorePassword);
                            passwordCorrect = true;
                        } catch (Exception e) {
                            System.out.println("Falsches Passwort. Bitte versuchen Sie es erneut.");
                        }
                    } else if ("pem".equals(fileType)) {
                        passwordCorrect = true;
                    } else {
                        System.out.println("Unbekanntes Zielformat. Das Programm wird beendet.");
                        return;
                    }
                }
                System.out.println("Geben Sie das Ausgabeverzeichnis für die Zertifikatskette ein:");
                String outputDirectory = scanner.nextLine().trim();

                while (true) {
                    Path outputDirPath = Paths.get(outputDirectory);
                    if (!Files.exists(outputDirPath) || !Files.isDirectory(outputDirPath)) {
                        System.out.println("Das angegebene Ausgabeverzeichnis existiert nicht oder ist kein Verzeichnis. Bitte versuchen Sie es erneut:");
                        outputDirectory = scanner.nextLine().trim();
                    } else {
                        break;
                    }
                }

                System.out.println("Geben Sie den gewünschten Dateinamen für die Zertifikatskette ein (ohne Dateierweiterung):");
                String fileName = scanner.nextLine().trim();
                String pemFileName = fileName + ".pem";
                Path certChainFilePath = Paths.get(outputDirectory, pemFileName);

                if ("ClearPass".equalsIgnoreCase(chainChoice)) {
                    arrangeClearPassChain(certChainFilePath);
                } else if ("Innovaphone".equalsIgnoreCase(chainChoice)) {
                    arrangeInnovaphoneChain(certChainFilePath);
                }
            } else {
                System.out.println("Ungültige Zertifikatskette. Das Programm wird beendet.");
                return;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        System.out.println("Möchten Sie das PEM-Zertifikat in eine PFX-Datei konvertieren? (ja/nein):");
        String convertToPfx = scanner.nextLine().trim();
        while (!"ja".equalsIgnoreCase(convertToPfx) && !"nein".equalsIgnoreCase(convertToPfx)) {
            System.out.println("Ungültige Eingabe. Bitte geben Sie 'ja' oder 'nein' ein:");
            convertToPfx = scanner.nextLine().trim();
        }
        if ("ja".equalsIgnoreCase(convertToPfx)) {
            // Erstelle PFX-Datei
            System.out.println("Geben Sie das Ausgabeverzeichnis für die PFX-Datei ein:");
            String outputDirectory = scanner.nextLine().trim();

            while (true) {
                Path outputDirPath = Paths.get(outputDirectory);
                if (!Files.exists(outputDirPath) || !Files.isDirectory(outputDirPath)) {
                    System.out.println("Das angegebene Ausgabeverzeichnis existiert nicht oder ist kein Verzeichnis. Bitte versuchen Sie es erneut:");
                    outputDirectory = scanner.nextLine().trim();
                } else {
                    break;
                }
            }

            System.out.println("Geben Sie den gewünschten Dateinamen für die PFX-Datei ein (ohne Dateierweiterung):");
            String pfxFileName = scanner.nextLine().trim() + ".pfx";
            Path pfxFilePath = Paths.get(outputDirectory, pfxFileName);

            // Erstelle PFX-Keystore mit der benutzerdefinierten Kette
            try {
                KeyStore pfxKeyStore = KeyStore.getInstance("PKCS12");
                pfxKeyStore.load(null, null);

                pfxKeyStore.setKeyEntry("privateKey", privateKey, keystorePassword.toCharArray(), chain);

                saveAsPfx(pfxKeyStore, keystorePassword, pfxFilePath);
                System.out.printf("Wrote %s\n", pfxFilePath);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Die Konvertierung in eine PFX-Datei wurde abgebrochen.");
        }
    }
    private static String getFileType(Path file) {
        String fileName = file.getFileName().toString();
        return fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
    }
    private static void setupKeyStore(Path file, String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(file), keystorePassword.toCharArray());

        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate[] certificateChain = keyStore.getCertificateChain(alias);

            if (certificateChain != null) {
                X509Certificate[] x509CertificateChain = Arrays.copyOf(certificateChain, certificateChain.length, X509Certificate[].class);

                var list = Arrays.asList(x509CertificateChain);

                Collections.reverse(list);

                x509CertificateChain = list.toArray(new X509Certificate[0]);

                chain = x509CertificateChain;
                for (int i = 0; i < x509CertificateChain.length; i++) {
                    X509Certificate x509Cert = x509CertificateChain[i];
                    printCertificateDetails(alias + " - Certificate " + (i + 1), x509Cert);
                }
                privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());
            }
        }
    }
    private static void printCertificateDetails(String alias, X509Certificate x509Cert) {
        System.out.println("Zertifikat: " + alias);

        String certificateType = identifyCertificateType(x509Cert);
        System.out.println("Typ: " + certificateType);

        System.out.println("Aussteller: " + x509Cert.getIssuerX500Principal());
        System.out.println("Inhaber: " + x509Cert.getSubjectX500Principal());
    }
    private static void saveAsPfx(KeyStore keyStore, String password, Path outputPath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outputPath.toString())) {
            keyStore.store(fos, password.toCharArray());
        }
    }
    private static String identifyCertificateType(X509Certificate certificates) {
        Map<String, Predicate<X509Certificate>> conditions = new HashMap<>();
        String[] certTypes = {"Ca-Zertifikat","Intermediate01","Intermediate02","Root"};

        // Umgekehrte Reihenfolge der Zertifikate im Array
        List<X509Certificate> certificateList = new ArrayList<>(Arrays.asList(certificates));
        Collections.reverse(certificateList);
        X509Certificate[] reversedCertificates = certificateList.toArray(new X509Certificate[0]);

        conditions.put("Root", cert -> {
            if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                rootCertificate = cert;
                return true;
            }
            return false;
        });
        conditions.put("Intermediate02", cert -> {
            if (rootCertificate != null && cert.getIssuerX500Principal().equals(rootCertificate.getSubjectX500Principal())) {
                intermediate02Certificate = cert;
                return true;
            }
            return false;
        });
        conditions.put("Intermediate01", cert -> {
            if (intermediate02Certificate != null && cert.getIssuerX500Principal().equals(intermediate02Certificate.getSubjectX500Principal())) {
                intermediate01Certificate = cert;
                return true;
            }
            return false;
        });
        conditions.put("Ca-Zertifikat", cert -> {
            if (intermediate01Certificate != null && cert.getIssuerX500Principal().equals(intermediate01Certificate.getSubjectX500Principal())) {
                CACertificate = cert;
                return true;
            }
            return false;
        });

        for (String certType : certTypes) {
            Predicate<X509Certificate> condition = conditions.get(certType);
            for (X509Certificate x509Cert : reversedCertificates) {
                if (condition.test(x509Cert)) {
                    return certType;
                }
            }
        }

        return "Unbekannt";
    }

    private static void arrangeInnovaphoneChain(Path certChainFilePath) throws IOException, CertificateEncodingException {
        // Definiere die Reihenfolge der Zertifikate
        X509Certificate[] certsInOrder = {
                CACertificate,
                intermediate01Certificate,
                intermediate02Certificate,
                rootCertificate
        };

        chain = certsInOrder;
        StringBuilder certChainStr = new StringBuilder();

        for (X509Certificate cert : certsInOrder) {
            certChainStr.append("-----BEGIN CERTIFICATE-----\n");
            certChainStr.append(encodeToBase64(cert.getEncoded())).append("\n");
            certChainStr.append("-----END CERTIFICATE-----\n");
        }

        certChainStr.append("-----BEGIN PRIVATE KEY-----\n");
        certChainStr.append(encodeToBase64(privateKey.getEncoded())).append("\n");
        certChainStr.append("-----END PRIVATE KEY-----\n");

        writeToFile(certChainFilePath, certChainStr.toString());

        System.out.printf("Wrote %s\n", certChainFilePath);
    }

    private static void arrangeClearPassChain(Path certChainFilePath) throws IOException, CertificateEncodingException {
        X509Certificate[] certsInOrder = {
                CACertificate,
                intermediate01Certificate,
                intermediate02Certificate,
                rootCertificate
        };

        StringBuilder certChainStr = new StringBuilder();

        for (X509Certificate cert : certsInOrder) {
            certChainStr.append("-----BEGIN CERTIFICATE-----\n");
            certChainStr.append(encodeToBase64(cert.getEncoded())).append("\n");
            certChainStr.append("-----END CERTIFICATE-----\n");
        }

        writeToFile(certChainFilePath, certChainStr.toString());

        System.out.printf("Wrote %s\n", certChainFilePath);
    }
    private static String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static void writeToFile(Path path, String content) throws IOException {
        Files.write(path, content.getBytes());
    }
}



