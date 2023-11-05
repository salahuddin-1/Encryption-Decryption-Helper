import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dart_des/dart_des.dart';
import 'package:string_validator/string_validator.dart';

class DES3EncryptionUtility {
  /// This is the key that we will use for encryption and decryption
  /// The key is in hexadecimal format
  /// Length of the string is 48
  /// 48 characters = 24 bytes = 192 bits
  /// every 2 characters = 1 byte = 8 bits in hexadecimal format
  static List<int> key = hex.decode(
    '0123456789ABCDEFFEDCBA98765432100123456789ABCDEF',
  );

  DES3EncryptionUtility._();

  static String encrypt({
    required String cardNumber,
  }) {
    /// Step 1: Create a DES3 object, which requires a key, mode and padding
    /// type
    /// Key is in Hexadecimal format
    /// Mode is ECB - Where each block of data is encrypted independently
    /// Padding type is PKCS7 - Where the data is padded if it not fits
    /// the block size
    DES3 desECB = DES3(
      key: key,
      mode: DESMode.ECB,
      paddingType: DESPaddingType.PKCS7,
    );

    /// Step 2: Convert the data to be encrypted to Uint8List format (bytes)
    List<int> cardNumberBytes = cardNumber.codeUnits;

    /// Step 3: Encrypt the data using the DES3 object, which returns the
    /// encrypted data in Uint8List format
    List<int> encryptedBytes = desECB.encrypt(
      cardNumberBytes,
    );

    /// Step 4: Convert the encrypted data (Uint8List) to base64 format
    /// for sending to the server
    String base64EncodedStr = base64Encode(
      encryptedBytes,
    );

    return base64EncodedStr;
  }

  static String decrypt({
    required String cardNo,
  }) {
    /// Step 1: Create a DES3 object, which requires a key, mode and padding
    DES3 desECB = DES3(
      key: key,
      mode: DESMode.ECB,
      paddingType: DESPaddingType.PKCS7,
    );

    /// [IF HEXADECIMAL]
    /// Step 2: Check if the card number is in hexadecimal format
    if (isHexadecimal(cardNo)) {
      /// Step 3: If the card number is in hexadecimal format then,
      /// convert the card number to bytes (Uint8List)
      List<int> encryptedBytes = hex.decode(
        cardNo,
      );

      /// Step 4: Decrypt the data using the DES3 object, which returns the
      /// decrypted data in Uint8List format
      List<int> decryptedBytes = desECB.decrypt(
        encryptedBytes,
      );

      return _removeNonNumericCharacters(
        decryptedBytes: decryptedBytes,
      );
    }

    /// [IF BASE64]

    Uint8List encryptedBytes = base64.decode(
      cardNo,
    );

    List<int> decryptedBytes = desECB.decrypt(
      encryptedBytes,
    );

    return _removeNonNumericCharacters(
      decryptedBytes: decryptedBytes,
    );
  }

  static String _removeNonNumericCharacters({
    required List<int> decryptedBytes,
  }) {
    /// Parse the Uint8List to String
    /// for example: [65, 66, 67] to "ABC"
    String decryptedString = String.fromCharCodes(
      decryptedBytes,
    );

    /// Remove all the non-numeric characters
    /// for example: "ABC123" to "123"
    return decryptedString.replaceAll(RegExp(r'[^0-9]'), '');
  }
}
