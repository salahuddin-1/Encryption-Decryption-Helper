import 'dart:convert';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:rsa_encrypt/rsa_encrypt.dart';

class RSAEncryptionUtility {
  /// Encrypt our random key (our secret key) with server's public key using
  /// RSA algorithm
  String encryptRandomKey({
    required String randomKey,

    /// BACKEND PUBLIC KEY
    required String serverPublicKey,
  }) {
    /// This class helps us to generate RSA keys
    RsaKeyHelper rsaKeyHelper = RsaKeyHelper();

    /// parsePublicKeyFromPem cleans the public key
    /// i.e. removes the header and footer of PEM string
    /// removes spaces, newlines and other characters from the string
    /// Example: The public key generated from the backend is
    ///
    /// Input
    /// -----BEGIN PUBLIC KEY-----
    /// MIIBIjANBgkqh
    /// kiG9w0BAQEFAAOCA
    /// \Q8AMIIBCgKCAQEAw3
    /// Z3Z3Z3Z3Z3Z3Z3Z3Z3
    /// -----END PUBLIC KEY-----
    ///
    /// Output
    /// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw3Z3Z3Z3Z3Z3Z3Z3Z3Z3
    RSAPublicKey _rsaPublicKeyObj = rsaKeyHelper.parsePublicKeyFromPem(
      serverPublicKey,
    );

    /// The algorithm object with the public key and encoding
    /// RSAEncoding.PKCS1 is not recommended due to security reasons
    RSA algo = RSA(
      publicKey: _rsaPublicKeyObj,
      encoding: RSAEncoding.OAEP,
    );

    /// Step 1: Create an encrypter object
    /// Step 2: The encrypter object requires an Algorithm object
    /// Step 3: Create the Algorithm object i.e. RSA
    /// Step 4: The Algorithm object i.e. RSA requires 2 parameters
    ///        i.e. publicKey and encoding
    /// Step 5: Create the publicKey object from our server's public key
    /// using the parsePublicKeyFromPem method of RsaKeyHelper class
    /// Step 6: The publicKey object requires a public key in the form of String
    /// Step 7: Create the RSAKeyHelper object first
    /// Step 8: Using the encrypter object encrypt the randomKey and
    /// return it with base64 encoding
    final encrypter = Encrypter(algo);

    /// Encrypt the randomKey with the encrypter object
    final encryptedKeyObj = encrypter.encrypt(
      randomKey,
    );

    print("encrypted key ${encryptedKeyObj.base64}");

    /// Return the encrypted key in base64 format
    return encryptedKeyObj.base64;
  }

  final test32CharsKey = "I2ykALnZj96DF9ddwcpbAKrgO6y2wMn6";

  String dummyServersPublicKey =
      "MIICCgKCAgEAzhyueSVNaIUxxct7ukSrsIyP607imDkiD4yCFmEhj3eUZR5/R0aWpoc7ggSKbhx/mxKjsPdr8MOAft5x04V09eSKWHO4/t0TmN9y2FYG5OOGgu22DuXxVNj2CgR7Gdr+cYQKt9EvKZUsZPX3qpGqLrOOJUikz4D7nTi2pOJXsLt+HrFjz8xt4HHzzET3izRg2LQBzzFPucYafseOt5TqrGKsUF1KQZ2l3wUMRgSTzJMDVqGQCF01JNRQiksmqAradrHQPiyzz1HfzYNwe7QiZ4SjhUnPmpSu9R9Lpf03tQhsEvuU7rLAz3veEwDCLavYO7yRwYjjFPzFp5Xa2TyZYPgsGe45Hmp5NWU3XU34Uemi/0peIq72ed20s8GScGRrmG2szB0FZ7h4gBGvaSJCQPUdh5ObPHFVWxs6A+GYag8Nk6bxOeNVQ+p1R1FQxjyBy4OJSzZ6gAoD2gsOaREepnrpUjHHqy4qYP6y25RvlDNK9WUmgOGaCrib/U96mIt41RhXsaCqSrT280OPRBSSnF1ycrjY1hN8iYhRT4DV31IvCU26MljgwfqR/056j5VUpWWyw0cL+LwyJn0YXPhRDeyy081ulLAEcknZgSVl3qcQSdlNCvM8m+OQAMlvU+6oM6ktQ0F+X/cVLR2vNQ6+ACrjk89MdtRQecRpKSWMYsECAwEAAQ==";

  String decryptRandomKey({
    required String encryptedRandomKey,

    /// BACKEND PUBLIC KEY
    required String serverPublicKey,
  }) {
    RsaKeyHelper rsaKeyHelper = RsaKeyHelper();

    RSAPublicKey _rsaPublicKeyObj = rsaKeyHelper.parsePublicKeyFromPem(
      serverPublicKey,
    );

    RSA algo = RSA(
      publicKey: _rsaPublicKeyObj,
      encoding: RSAEncoding.OAEP,
    );

    Uint8List bytes = base64.decode(serverPublicKey);

    final encrypter = Encrypter(algo);

    final encryptedObj = Encrypted(bytes);

    print("decrypted key ${encrypter.decrypt(encryptedObj)}");

    return encrypter.decrypt(encryptedObj);
  }

  // --------------------------------------------------------------------------

  /// Generate RSA key pair of PUBLIC and PRIVATE keys
  /// In RSA, both of these keys are required and we don't have
  /// backend's private key, so for learning purpose we will generate
  /// our own key pair
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAkeyPair(
    pc.SecureRandom secureRandom, {
    /// Size of the key in bits
    int bitLength = 2048,
  }) {
    /// This is a common key generator, you can pass specific algorithm
    /// name to generate keys of that algorithm, here we are using RSA
    // final keyGen = KeyGenerator('RSA'); // From the registry
    // You can use this or the below one

    /// This is a specific key generator designed only for RSA
    /// Step 1: Create a key generator object
    final keyGen = RSAKeyGenerator();

    /// Step 2: Create a key generator parameters object by
    /// specifying the public exponent and the bit length
    final keyParams = RSAKeyGeneratorParameters(
      BigInt.from(65537), // The Public Exponent (Prime number)
      bitLength,
      // (64) is the Certainty level that the generated numbers are prime
      // the higher the value, the more is the certainty, the more is the time
      // to generate the keys
      64,
    );

    /// Step 3: Create a parameters with random object and pass the
    /// key generator parameters object and the secure random object
    /// You can create any CipherParameters like
    /// (ParametersWithIV, ParametersWithRandom, ParametersWithSalt, etc.)
    final params = ParametersWithRandom(
      keyParams,
      secureRandom,
    );

    /// Step 4: Initialize the key generator with the parameters
    keyGen.init(params);

    /// Step 5: Generate the key pair
    final pair = keyGen.generateKeyPair();

    /// Step 6: Return the key pair and typecast the keys to RSA keys
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      pair.publicKey as RSAPublicKey,
      pair.privateKey as RSAPrivateKey,
    );
  }

  /// HASH FUNCTION
  /// This method create the digital signature of the data using our
  /// private key
  /// It creates a HASH VALUE/DIGEST of the data using SHA256 algorithm
  /// For example, if the data is "Hello World!" then the hash value
  /// will be "a5d6f8b9c0a1b2c3d4e5f6a7b8c9d0e1"
  /// but we are returning the hash value in Uint8List format (in bytes)
  Uint8List rsaSign({
    required RSAPrivateKey privateKey,
    required Uint8List dataToSign,
  }) {
    /// Step 1: Create a signer object with the HASH algorithm type
    /// and the OID of the HASH algorithm
    /// Don't worry about the OID, it is just a unique identifier
    /// associated with the HASH algorithm i.e. SHA256
    final signer = pc.RSASigner(
      SHA256Digest(),
      '0609608648016503040201',
    );

    //  initialize with true, which means sign
    signer.init(
      true,
      PrivateKeyParameter<RSAPrivateKey>(privateKey),
    );

    final hashDigest = signer.generateSignature(
      dataToSign,
    );

    print("sig ${hashDigest.hashCode}");
    print("sig ${hashDigest.bytes}");

    return hashDigest.bytes;
  }

  /// VERIFY the HASH VALUE/DIGEST
  /// This method obtains the HASH VALUE/DIGEST of the decrypted data and
  /// compares it with the HASH VALUE/DIGEST obtained from the receiver
  /// If the HASH VALUE/DIGEST matches then the data is not tampered
  bool rsaVerify({
    required RSAPublicKey publicKey,

    /// Actual Decrypted data
    required Uint8List decryptedData,

    /// Raw Hash value from the receiver
    required Uint8List hashObtained,
  }) {
    final verifier = pc.RSASigner(
      SHA256Digest(),
      '0609608648016503040201',
    );

    // initialize with false, which means verify
    verifier.init(
      false,
      PublicKeyParameter<RSAPublicKey>(publicKey),
    );

    final sig = RSASignature(hashObtained);

    /// The verifier.verifySignature() compare the HASH calculated from
    /// the decrypted data with the HASH obtained from the receiver
    /// If the HASH matches then the data is not tampered and returns true
    /// else returns false
    try {
      return verifier.verifySignature(
        decryptedData,
        sig,
      );
    } on ArgumentError {
      /// If the data is tampered then the parsing of the signature will fail
      /// so error will be thrown and we will return false
      return false; // for Pointy Castle 1.0.2 when signature has been modified
    }
  }
}
