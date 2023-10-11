import requests
from requests.auth import HTTPBasicAuth
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Convert PFX to PEM
def pfx_to_certs(pfx_path, pfx_password):
    with open(pfx_path, "rb") as f:
        pfx_data = f.read()

    private_key = None
    certificate = None

    # Load the PKCS12 data
    p12 = serialization.load_pem_pkcs12(pfx_data, pfx_password.encode())

    private_key = p12[0].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    certificate = p12[1].public_bytes(serialization.Encoding.PEM)

    return (certificate, private_key)


# Your SOAP endpoint
url = "https://bp-b2bservice.mijnpost.pat.postnl.nl/B2BService.svc"

# Set your username and password
username = "username"
password = "password"

# SOAP request headers
headers = {
    "Content-Type": "text/xml",
    "SOAPAction": "GetValidationResultV1",
}

# Load the SOAP request body from the XML file
with open("GetValidationResultV1.xml", "r") as file:
    body = file.read()

# Extract PEM certificate and key from PFX
pfx_path = "certificate.pfx"
pfx_password = "your_pfx_password"
cert, key = pfx_to_certs(pfx_path, pfx_password)

# Make the request with basic authentication and client certificate
response = requests.post(
    url,
    headers=headers,
    data=body,
    auth=HTTPBasicAuth(username, password),
    cert=(cert, key),
)

# Print the response content
print(response.content)
