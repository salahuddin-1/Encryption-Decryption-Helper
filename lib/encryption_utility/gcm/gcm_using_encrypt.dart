import 'package:encrypt/encrypt.dart';

class GCMUsingEncrypt {
  /// ENCRYPT USING GCM
  /// Package (encrypt)
  String encrypt({
    required String data,
    required String key,
    required IV iv,
  }) {
    /// This key is generated from a 32 byte string
    final keyObject = Key.fromUtf8(
      key,
    );

    /// Note: GCM is basically a mode of operation for AES
    /// Step 1: Create an encrypter object
    /// Step 2: The encrypter object requires an Algorithm object
    /// Step 3: Create the Algorithm object i.e. AES
    /// Step 4: The Algorithm object i.e. AES requires a Key object
    /// Step 5: Create the Key object from our secret key
    /// Step 6: The Key object requires a key in the form of String
    final encrypter = Encrypter(
      AES(
        keyObject,
        mode: AESMode.gcm, // GCM mode
      ),
    );

    /// Step 7: Encrypt the data using the encrypter object with the IV
    final encryptedText = encrypter.encrypt(
      data,
      iv: iv,
    );

    print('Encrypted Text: ${encryptedText.base64}');

    return encryptedText.base64;
  }

  /// DECRYPT USING GCM
  /// Package (encrypt)
  String decrypt({
    required String encryptedText,
    required String key,
    required IV iv,
  }) {
    /// Decryption is the same as encryption except for the fact that
    /// the method decrypt is used instead of encrypt
    /// and the encrypted data is converted to Encrypted object
    // Note: The encryptedData will come  in base64 format

    final keyObject = Key.fromUtf8(
      key,
    );

    final encrypter = Encrypter(
      AES(
        keyObject,
        mode: AESMode.gcm,
      ),
    );

    final decryptedText = encrypter.decrypt(
      Encrypted.fromBase64(encryptedText),
      iv: iv,
    );

    print('Decrypted Text: $decryptedText');

    return decryptedText;
  }
}
