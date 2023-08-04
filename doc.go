/*
Package easyecc ties together several other common packages and makes it easy to
perform common elliptic key cryptography operations on multiple curves
(including secp256k1, used by Bitcoin, see https://en.bitcoin.it/wiki/Secp256k1).

In addition to secp256k1, P-256, P-384 and P-521 are also supported.

These operations include:

-- Creating private keys, in various ways

-- Saving private key to file, possibly passphrase-protected

-- Reading and decrypting private key from file

-- Signing data using the private key and verifying with the public key (ECDSA)

-- Encrypting data using a symmetric encryption key derived from private key/public key pair (ECDH)

See the examples for more information.
*/
package easyecc
