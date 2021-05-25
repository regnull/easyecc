/*
Package easyecc ties together several other common packages and makes it easy to
perform common elliptic key cryptography operations (secp256k1, used by Bitcoin).

These operations include:

-- Creating private keys, in various ways

-- Saving private key to file, possibly passphrase-protected

-- Reading and decrypting private key from file

-- Signing data using the private key and verifying with the public key

-- Encrypting data using a symmetric encryption key derived from private key/public key pair

See the examples for more information.
*/
package easyecc
