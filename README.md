# fty-lib-certificate

Helper class for SSL certificate handling

`fty-lib-certificate` helps to create and manage a SSL certificate and a Certificate Signing Request (CSR).

Capabilities:
- create a public-private key pair
- create a self-signed certificate
- create a Certificate Signing Request (CSR)

## How to clone and build
```
git clone https://github.com/42ity/fty-lib-certificate.git

cd fty-lib-certificate

./autogen.sh
./configure

make

make check  #run self test
```

## Examples

### Create an RSA key pair and export PEM
```
Keys keyPair = Keys::generateRSA(2048);
std::string privateKeyPem = keyPair.getPem();
std::string publicKeyPem  = keyPair.getPublicKey().getPem();
```

### Create a self-signed certificate
```
Keys keyPair = Keys::generateRSA(2048);

CertificateConfig config;

// define your configuration here
config.setVersion(<version>);
config.setValidFrom(<start_timestamp>);
config.setValidTo(<end_timestamp>);
config.setCountry(<country>);
config.setState(<state>);
config.setLocality(<locality>);
config.setOrganization(<organization>);
config.setOrganizationUnit(<organization_unit>);
config.setCommonName(<common_name>);
config.setEmail(<email>);
config.setIpList({<ip1>,<ip2>});
config.setDnsList({<dns1>,<dns2>});

CertificateX509 cert = CertificateX509::selfSignSha256(keyPair, config);
```

### Create a Certificate Signing Request (CSR)
```
Keys keyPair = Keys::generateRSA(2048);

CertificateConfig config;

// define your configuration here
config.setVersion(<version>);
config.setCountry(<country>);
config.setState(<state>);
config.setLocality(<locality>);
config.setOrganization(<organization>);
config.setOrganizationUnit(<organization_unit>);
config.setCommonName(<common_name>);
config.setEmail(<email>);
config.setIpList({<ip1>,<ip2>});
config.setDnsList({<dns1>,<dns2>});

CsrX509 csr = CsrX509::generateCsr(keyPair, config);
```