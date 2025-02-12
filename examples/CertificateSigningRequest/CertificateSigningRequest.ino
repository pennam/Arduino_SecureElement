/*
  Generate CSR (Certificate Signing Request)

  This sketch can be used to generate a CSR for a private key
  generated in an ECC508/ECC608 or SE050 crypto chip slot.

  If the ECC508/ECC608 is not configured and locked it prompts
  the user to configure and lock the chip with a default TLS
  configuration.

  The user is prompted for the following information that is contained
  in the generated CSR:
  - country
  - state or province
  - locality
  - organization
  - organizational unit
  - common name

  The user can also select a slot number to use for the private key
  A new private key can also be generated in this slot.

  The circuit:
  - A board equipped with ECC508 or ECC608 or SE050 chip

  This example code is in the public domain.
*/

#include <Arduino_SecureElement.h>
#include <utility/SElementCSR.h>


void setup() {
  Serial.begin(9600);
  while (!Serial);

  SecureElement secureElement;

  if (!secureElement.begin()) {
    Serial.println("No SecureElement present!");
    while (1);
  }

  String serialNumber = secureElement.serialNumber();

  Serial.print("SecureElement Serial Number = ");
  Serial.println(serialNumber);
  Serial.println();

  if (!secureElement.locked()) {
    String lock = promptAndReadLine("The SecureElement on your board is not locked, would you like to PERMANENTLY configure and lock it now? (y/N)", "N");
    lock.toLowerCase();

    if (!lock.startsWith("y")) {
      Serial.println("Unfortunately you can't proceed without locking it :(");
      while (1);
    }

    if (!secureElement.writeConfiguration()) {
      Serial.println("Writing SecureElement configuration failed!");
      while (1);
    }

    if (!secureElement.lock()) {
      Serial.println("Locking SecureElement configuration failed!");
      while (1);
    }

    Serial.println("SecureElement locked successfully");
    Serial.println();
  }

  Serial.println("Hi there, in order to generate a new CSR for your board, we'll need the following information ...");
  Serial.println();

  String country            = promptAndReadLine("Country Name (2 letter code)", "");
  String stateOrProvince    = promptAndReadLine("State or Province Name (full name)", "");
  String locality           = promptAndReadLine("Locality Name (eg, city)", "");
  String organization       = promptAndReadLine("Organization Name (eg, company)", "");
  String organizationalUnit = promptAndReadLine("Organizational Unit Name (eg, section)", "");
  String common             = promptAndReadLine("Common Name (e.g. server FQDN or YOUR name)", serialNumber.c_str());
  String slot               = promptAndReadLine("What slot would you like to use? (0 - 4)", "0");
  String generateNewKey     = promptAndReadLine("Would you like to generate a new private key? (Y/n)", "Y");

  Serial.println();

  generateNewKey.toLowerCase();

  ECP256Certificate CSR;

  CSR.begin();
  CSR.setSubjectCountryName(country);
  CSR.setSubjectStateProvinceName(stateOrProvince);
  CSR.setSubjectLocalityName(locality);
  CSR.setSubjectOrganizationName(organization);
  CSR.setSubjectOrganizationalUnitName(organizationalUnit);
  CSR.setSubjectCommonName(common);

  if (!SElementCSR::build(secureElement, CSR, slot.toInt(), generateNewKey.startsWith("y"))) {
    Serial.println("Error starting CSR generation!");
    while (1);
  }

  String csr = CSR.getCSRPEM();

  if (!csr) {
    Serial.println("Error generating CSR!");
    while (1);
  }

  Serial.println("Here's your CSR, enjoy!");
  Serial.println();
  Serial.println(csr);
}

void loop() {
  // do nothing
}

String promptAndReadLine(const char* prompt, const char* defaultValue) {
  Serial.print(prompt);
  Serial.print(" [");
  Serial.print(defaultValue);
  Serial.print("]: ");

  String s = readLine();

  if (s.length() == 0) {
    s = defaultValue;
  }

  Serial.println(s);

  return s;
}

String readLine() {
  String line;

  while (1) {
    if (Serial.available()) {
      char c = Serial.read();

      if (c == '\r') {
        // ignore
        continue;
      } else if (c == '\n') {
        break;
      }

      line += c;
    }
  }

  return line;
}
