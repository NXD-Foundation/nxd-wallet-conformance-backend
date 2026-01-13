#!/bin/bash
# Script to set up Let's Encrypt certificates for x509 authentication
# 
# Usage:
#   ./setup-letsencrypt-certs.sh
#   (Uses certificates from ./certbot/conf/live/dev-i4mlab.aegean.gr/)
#
# Or with custom paths:
#   ./setup-letsencrypt-certs.sh /path/to/cert.pem /path/to/privkey.pem

set -e

# Default to certbot folder in project root
DEFAULT_CERT_FILE="./certbot/conf/live/dev-i4mlab.aegean.gr/fullchain.pem"
DEFAULT_PRIVKEY_FILE="./certbot/conf/live/dev-i4mlab.aegean.gr/privkey.pem"

if [ $# -eq 0 ]; then
    # No arguments - use default certbot location
    CERT_FILE="$DEFAULT_CERT_FILE"
    PRIVKEY_FILE="$DEFAULT_PRIVKEY_FILE"
elif [ $# -eq 2 ]; then
    # Two arguments provided - use custom paths
    CERT_FILE="$1"
    PRIVKEY_FILE="$2"
else
    echo "Usage: $0 [certificate.pem] [private-key.pem]"
    echo ""
    echo "If no arguments provided, uses:"
    echo "  Certificate: $DEFAULT_CERT_FILE"
    echo "  Private Key: $DEFAULT_PRIVKEY_FILE"
    echo ""
    echo "Or provide custom paths:"
    echo "  $0 /path/to/cert.pem /path/to/privkey.pem"
    exit 1
fi

if [ ! -f "$CERT_FILE" ]; then
    echo "Error: Certificate file not found: $CERT_FILE"
    exit 1
fi

if [ ! -f "$PRIVKEY_FILE" ]; then
    echo "Error: Private key file not found: $PRIVKEY_FILE"
    exit 1
fi

echo "Setting up Let's Encrypt certificates..."
echo "Certificate: $CERT_FILE"
echo "Private Key: $PRIVKEY_FILE"
echo ""

# Extract the leaf certificate (first certificate in the chain)
echo "Extracting leaf certificate..."
LEAF_CERT=$(openssl x509 -in "$CERT_FILE" -outform PEM)

# Detect certificate type (RSA or EC)
CERT_TYPE=$(openssl x509 -in "$CERT_FILE" -text -noout | grep "Public Key Algorithm" | grep -o "rsaEncryption\|id-ecPublicKey" || echo "unknown")
if echo "$CERT_TYPE" | grep -q "rsaEncryption"; then
    CERT_TYPE="RSA"
elif echo "$CERT_TYPE" | grep -q "id-ecPublicKey"; then
    CERT_TYPE="EC"
else
    CERT_TYPE="unknown"
fi

echo "Detected certificate type: $CERT_TYPE"
echo ""

# Convert private key to PKCS8 format
echo "Converting private key to PKCS8 format..."
PRIVKEY_PKCS8=$(openssl pkcs8 -topk8 -inform PEM -outform PEM -in "$PRIVKEY_FILE" -nocrypt)

# Verify the certificate has the required SAN entries
echo ""
echo "Verifying certificate SAN entries..."
SAN_ENTRIES=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A 3 "X509v3 Subject Alternative Name" | grep "DNS:" || echo "")
if echo "$SAN_ENTRIES" | grep -q "dev-i4mlab.aegean.gr"; then
    echo "✓ Certificate contains dev-i4mlab.aegean.gr"
else
    echo "⚠ Warning: Certificate may not contain dev-i4mlab.aegean.gr in SAN"
fi

if echo "$SAN_ENTRIES" | grep -q "www.dev-i4mlab.aegean.gr"; then
    echo "✓ Certificate contains www.dev-i4mlab.aegean.gr"
else
    echo "⚠ Warning: Certificate may not contain www.dev-i4mlab.aegean.gr in SAN"
fi

echo ""
echo "SAN entries found:"
echo "$SAN_ENTRIES"
echo ""

# Backup existing certificates
echo "Backing up existing certificates..."
for dir in x509 x509EC wallet-client/x509 wallet-client/x509EC; do
    if [ -f "$dir/client_certificate.crt" ]; then
        cp "$dir/client_certificate.crt" "$dir/client_certificate.crt.backup.$(date +%Y%m%d_%H%M%S)"
        echo "  Backed up $dir/client_certificate.crt"
    fi
    if [ -f "$dir/client_private_pkcs8.key" ]; then
        cp "$dir/client_private_pkcs8.key" "$dir/client_private_pkcs8.key.backup.$(date +%Y%m%d_%H%M%S)"
        echo "  Backed up $dir/client_private_pkcs8.key"
    fi
done

# Install certificate and private key based on type
echo ""
echo "Installing certificates..."

if [ "$CERT_TYPE" = "RSA" ]; then
    # RSA certificate - install to x509 directories
    echo "$LEAF_CERT" > x509/client_certificate.crt
    echo "$PRIVKEY_PKCS8" > x509/client_private_pkcs8.key
    echo "  ✓ Installed to x509/ (RSA)"
    
    echo "$LEAF_CERT" > wallet-client/x509/client_certificate.crt
    echo "$PRIVKEY_PKCS8" > wallet-client/x509/client_private_pkcs8.key
    echo "  ✓ Installed to wallet-client/x509/ (RSA)"
elif [ "$CERT_TYPE" = "EC" ]; then
    # EC certificate - install to x509EC directories
    echo "$LEAF_CERT" > x509EC/client_certificate.crt
    echo "$PRIVKEY_PKCS8" > x509EC/ec_private_pkcs8.key
    echo "  ✓ Installed to x509EC/ (EC)"
    
    echo "$LEAF_CERT" > wallet-client/x509EC/client_certificate.crt
    echo "$PRIVKEY_PKCS8" > wallet-client/x509EC/ec_private_pkcs8.key
    echo "  ✓ Installed to wallet-client/x509EC/ (EC)"
    
    echo ""
    echo "Note: EC certificate installed to x509EC directories."
    echo "      If you also need it in x509 directories, you'll need an RSA certificate."
else
    echo "  ⚠ Warning: Unknown certificate type. Installing to x509/ anyway..."
    echo "$LEAF_CERT" > x509/client_certificate.crt
    echo "$PRIVKEY_PKCS8" > x509/client_private_pkcs8.key
    echo "$LEAF_CERT" > wallet-client/x509/client_certificate.crt
    echo "$PRIVKEY_PKCS8" > wallet-client/x509/client_private_pkcs8.key
fi
echo ""
echo "✓ Setup complete!"
echo ""
echo "To verify, run:"
echo "  openssl x509 -in x509/client_certificate.crt -text -noout | grep -A 3 'Subject Alternative Name'"
