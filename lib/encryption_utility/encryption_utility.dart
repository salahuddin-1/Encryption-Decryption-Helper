import 'dart:convert';
import 'dart:math';

import 'package:encrypt/encrypt.dart';
import 'package:encryption_decryption_helper/encryption_utility/gcm/gcm_using_encrypt.dart';
import 'package:encryption_decryption_helper/encryption_utility/gcm/gcm_using_pointycastle.dart';

/// Steps
/// 1. Generate a random key
/// 2. Get the IV
/// 3. Create an encrypter using the key
/// 4. Encrypt the data using the encrypter and IV
/// 5. Get the encrypted data

/// Note: In CBOJ we are preferring the pointycastle package over the encrypt
/// package. The pointycastle package is customizable
/// We can pass desired parameters to the algorithm
/// The encrypt package uses it's own parameters internally and
/// in pointycastle we can manipulate the parameters

class EncryptionUtility {
  final _gcmUsingPointyCastle = GCMUsingPointyCastle();
  final _gcmUsingEncrypt = GCMUsingEncrypt();

  // Generates a random key of 32 characters
  // You can use any random key generator instead, but a strong one
  // so that it is not easy to crack
  String generateRandomKey() {
    const _chars =
        'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';

    Random _rnd = Random();

    String randomKey = String.fromCharCodes(
      Iterable.generate(
        32,
        (_) => _chars.codeUnitAt(
          _rnd.nextInt(_chars.length),
        ),
      ),
    );

    print('random key---->$randomKey');

    if (randomKey.length > 32) {
      return randomKey.substring(0, 32);
    }

    return randomKey;
  }

  final _testData = {
    "userName": "john44",
    "password": "12345",
    "loginType": "USER",
    "cipher": "abcdef12345",
    "appLoginPin": "111111",
  };

  final _test32CharsKey = "I2ykALnZj96DF9ddwcpbAKrgO6y2wMn6";

  IV get _testIV {
    final iv = IV.fromLength(16);

    return iv;
  }

  String encrypt() {
    String data = jsonEncode(
      _testData,
    );

    String encryptedBase64Data = _gcmUsingPointyCastle.encrypt(
      data: data,
      key: _test32CharsKey,
      nonce: _testIV.bytes,
    );

    print('Encrypted Data: $encryptedBase64Data');

    return encryptedBase64Data;
  }

  String decrypt(String encryptedBase64Data) {
    String decryptedData = _gcmUsingPointyCastle.decrypt(
      encryptedData: encryptedBase64Data,
      key: _test32CharsKey,
      nonce: _testIV.bytes,
    );

    print('Decrypted Data: $decryptedData');

    return decryptedData;
  }
}
