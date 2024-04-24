# CertificateConverter

This Java program allows for the detection of certificate formats (PEM or PFX) by reading a certificate, identifying individual certificates within it, and outputting them. Additionally, it facilitates the creation of a new certificate chain, which can be converted to PEM and, if desired, to PFX format.


## Installation

Install the [bcprov-jdk15on](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on)
library, version 1.70, from the website
## Usage

```python
Execute the application.
Enter the file path to the certificate.
Provide the password.
Select the target format (ClearPass or Innovaphone) for the certificate chain.
Specify the output directory and filename for the certificate chain.
Optional: Convert the PEM certificate to a PFX file
```
## Features
- Conversion of PEM files into temporary PFX files, password remains unchanged.
- Certificate detection

- Compilation of certificate chains for various platforms such as ClearPass and Innovaphone.

- Conversion to pfx possible


## Notes
The certificate that is loaded, especially the Pem, must have the correct “normal” certificatechain as follows Key certificate, Ca certificate, Intermediate, root 