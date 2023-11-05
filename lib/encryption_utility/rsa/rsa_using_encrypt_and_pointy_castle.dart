import 'dart:convert';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:encryption_decryption_helper/encryption_utility/encryption_utility.dart';
import 'package:encryption_decryption_helper/encryption_utility/rsa/rsa_encryption_utility.dart';
import 'package:pointycastle/export.dart';
import 'package:rsa_encrypt/rsa_encrypt.dart';

class RsaUsingEncryptAndPointyCastle {
  // Our common class holding test data and random key
  EncryptionUtility encryptionUtility = EncryptionUtility();

  // Our RSA encryption utility class holding methods to generate RSA key pair
  RSAEncryptionUtility rsaEncryptionUtility = RSAEncryptionUtility();

  RsaKeyHelper rsaKeyHelper = RsaKeyHelper();

  /// ENCRYPT USING RSA
  String encrypt({
    required String data,
    required RSAPublicKey? publicKey,
  }) {
    final encrypter = Encrypter(
      RSA(
        publicKey: publicKey,
      ),
    );

    final encryptedDataObj = encrypter.encrypt(data);

    print("encrypted ${encryptedDataObj.base64}");

    return encryptedDataObj.base64;
  }

  /// DECRYPT USING RSA
  String decrypt({
    required String encryptedData,
    required RSAPrivateKey? privateKey,
  }) {
    final encrypter = Encrypter(
      RSA(
        privateKey: privateKey,
      ),
    );

    final encryptedDataObj = Encrypted.fromBase64(encryptedData);
    String decryptedData = encrypter.decrypt(encryptedDataObj);

    print("decryptedData ${decryptedData}");

    return decryptedData;
  }

  /// [EXAMPLE 1]
  void example() {
    String randomKey = encryptionUtility.generateRandomKey();

    // final secureRandom = pc.SecureRandom('Fortuna'); // From the registry

    // The specific secure random object for Fortuna algorithm
    FortunaRandom secureRandom = FortunaRandom();

    // Get the bytes from the random key
    Uint8List randomKeyBytes = Uint8List.fromList(
      randomKey.codeUnits,
    );

    // Create a key parameter object with the random key bytes
    KeyParameter keyParameter = KeyParameter(
      randomKeyBytes,
    );

    // Initialize the secure random object with the key parameter
    secureRandom.seed(keyParameter);

    // Generate the RSA key pair
    final keyPair = rsaEncryptionUtility.generateRSAkeyPair(
      secureRandom,
    );

    String msg = "Hi, Encryption using RSA using encrypt package";

    String enryptedData = encrypt(
      data: msg,
      publicKey: keyPair.publicKey,
    );

    decrypt(
      encryptedData: enryptedData,
      privateKey: keyPair.privateKey,
    );
  }

  /// RSA Encryption using our own public key
  String encryptUsingMyPublicKey({
    required String data,
    required String publicKey,
  }) {
    /// Refer encryptRandomKey() method for explanation

    RSAPublicKey _rsaPublicKeyObj = rsaKeyHelper.parsePublicKeyFromPem(
      publicKey,
    );

    RSA algo = RSA(
      publicKey: _rsaPublicKeyObj,
      encoding: RSAEncoding.OAEP,
    );

    final encrypter = Encrypter(algo);

    /// Encrypt the randomKey with the encrypter object
    final encryptedKeyObj = encrypter.encrypt(
      data,
    );

    /// Return the encrypted key in base64 format
    return encryptedKeyObj.base64;
  }

  /// RSA Decryption using our own private key
  String decryptUsingMyPrivateKey({
    required String encryptedData,
    required String privateKey,
  }) {
    /// Refer encryptRandomKey() method for explanation
    RsaKeyHelper rsaKeyHelper = RsaKeyHelper();

    RSAPrivateKey _rsaPublicKeyObj = rsaKeyHelper.parsePrivateKeyFromPem(
      privateKey,
    );

    RSA algo = RSA(
      privateKey: _rsaPublicKeyObj,
      encoding: RSAEncoding.OAEP,
    );

    final encrypter = Encrypter(algo);

    /// Parse the encrypted data from base64 format to Uint8List format
    Uint8List bytes = base64.decode(encryptedData);

    final decryptedMsg = encrypter.decrypt(
      Encrypted(bytes),
    );

    print("decrypted msg ${decryptedMsg}");

    return decryptedMsg;
  }

  /// [EXAMPLE 2]
  /// ENCRYPT USING OUR OWN PUBLIC AND PRIVATE KEYS
  void exampleUsingOurPublicAndPrivateKeys() {
    String randomKey = encryptionUtility.generateRandomKey();

    // final secureRandom = pc.SecureRandom('Fortuna'); // From the registry

    // The specific secure random object for Fortuna algorithm
    FortunaRandom secureRandom = FortunaRandom();

    // Get the bytes from the random key
    Uint8List randomKeyBytes = Uint8List.fromList(
      randomKey.codeUnits,
    );

    // Create a key parameter object with the random key bytes
    KeyParameter keyParameter = KeyParameter(
      randomKeyBytes,
    );

    // Initialize the secure random object with the key parameter
    secureRandom.seed(keyParameter);

    // Generate the RSA key pair
    final keyPair = rsaEncryptionUtility.generateRSAkeyPair(
      secureRandom,
    );

    String msg =
        "Hi, Encryption using RSA using OUR OWN PUBLIC AND PRIVATE KEYS";

    final myPublicKey = rsaKeyHelper.encodePublicKeyToPemPKCS1(
      keyPair.publicKey,
    );

    // print(publicKey);

    final myPrivateKey = rsaKeyHelper.encodePrivateKeyToPemPKCS1(
      keyPair.privateKey,
    );

    // print(privateKey);

    final encryptedMsg = encryptUsingMyPublicKey(
      data: msg,
      publicKey: myPublicKey,
    );

    decryptUsingMyPrivateKey(
      encryptedData: encryptedMsg,
      privateKey: myPrivateKey,
    );
  }

  /// [EXAMPLE 3]
  /// RSA USING DIGITAL SIGNATURE
  /// This method is used to test the RSA Encryption and Decryption along with
  /// the Digital Signature
  void exampleUsingDigitalSignature() {
    EncryptionUtility encryptionUtility = EncryptionUtility();
    final randomKey = encryptionUtility.generateRandomKey();

    FortunaRandom secureRandom = FortunaRandom();
    // final secureRandom = pc.SecureRandom('Fortuna');

    secureRandom.seed(
      KeyParameter(
        Uint8List.fromList(randomKey.codeUnits),
      ),
    );

    final keyPair = rsaEncryptionUtility.generateRSAkeyPair(
      secureRandom,
    );

    String msg = "Hi, Digital Signature using RSA";

    final hash = rsaEncryptionUtility.rsaSign(
      privateKey: keyPair.privateKey,
      dataToSign: Uint8List.fromList(
        msg.codeUnits,
      ),
    );

    bool isSigned = rsaEncryptionUtility.rsaVerify(
      publicKey: keyPair.publicKey,
      decryptedData: Uint8List.fromList(
        msg.codeUnits,
        // [...msg.codeUnits, 0], // DATA ALTERED This will make the verification fail
      ),
      hashObtained: hash,
    );

    print(isSigned);
  }
}
