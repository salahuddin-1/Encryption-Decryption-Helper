import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

class GCMUsingPointyCastle {
  /// ENCRYPT USING GCM
  /// Package (pointycastle)
  String encrypt({
    required String data,
    required String key,

    /// IV
    required Uint8List nonce,
  }) {
    // Note: GCM is basically a mode of operation for AES

    Uint8List keyBytes = Uint8List.fromList(
      key.codeUnits,
    );

    KeyParameter keyParameter = KeyParameter(
      keyBytes,
    );

    final aesEngine = AESEngine()
      ..init(
        true,
        keyParameter,
      );

    /// Parameters for GCM or conditions for GCM
    /// Step 8: Create the AEADParameters object
    final params = AEADParameters(
      keyParameter, // KeyParameter
      128, // MAC Size in bits (The authentication tag size)
      nonce, // IV - Randomly generated value
      Uint8List(0), // Additional data, currently an empty list
    );

    /// Basically the encryption starts from here
    /// Step 1: Create a GCMBlockCipher object
    /// Step 2: The GCMBlockCipher object requires a BlockCipher object
    /// Step 3: Create the BlockCipher object i.e. AES
    /// Step 4: The BlockCipher object i.e AESEngine requires a KeyParameter
    /// Step 5: Create the KeyParameter object
    /// Step 6: The KeyParameter object requires a key in the form of Uint8List
    /// Step 7: Create the Uint8List object from the key
    /// Note: The key will be in the form of String and random
    final gcmBlockCipherObj = GCMBlockCipher(aesEngine);

    /// Step 9: Initialize the GCMBlockCipher object
    /// with true for encryption and false for decryption
    /// and with the parameters
    gcmBlockCipherObj.init(true, params);

    Uint8List dataBytes = Uint8List.fromList(
      data.codeUnits,
    );

    /// Step 10: Start the encryption process. But the process requires
    /// the data to be in Uint8List format
    /// Step 11: Convert the data (String) to Uint8List format and
    /// create a Uint8List object
    /// The encryption process will start and return the encrypted data
    /// also in Uint8List format
    Uint8List encryptedBytes = gcmBlockCipherObj.process(
      dataBytes,
    );

    /// Step 12: Convert the encrypted data (Uint8List) to a
    /// base64 String format to be passed to the server
    String encryptedData = base64Encode(
      encryptedBytes,
    );

    print("encryptedData $encryptedData");

    return encryptedData;
  }

  /// DECRYPT USING GCM
  /// Package (pointycastle)
  String decrypt({
    required String encryptedData,
    required String key,

    /// IV
    required Uint8List nonce,
  }) {
    /// Decryption is the same as encryption except for the fact that
    /// the GCMBlockCipher object is initialized with false for decryption
    /// and the encrypted data is passed to the process method
    /// instead of the data
    // Note: The encryptedData will come  in base64 format

    Uint8List keyBytes = Uint8List.fromList(
      key.codeUnits,
    );

    KeyParameter keyParameter = KeyParameter(
      keyBytes,
    );

    final aesEngine = AESEngine()
      ..init(
        false, // false for decryption
        keyParameter,
      );

    final gcmBlockCipherObj = GCMBlockCipher(aesEngine);

    final params = AEADParameters(
      keyParameter,
      128,
      nonce,
      Uint8List(0),
    );

    gcmBlockCipherObj.init(
      false, // false for decryption
      params,
    );

    /// The encrypted data is in base64 format
    /// So, we need to convert it to Uint8List format
    /// because the process method requires the data to be in
    /// Uint8List format for decryption
    Uint8List encryptedDataBytes = base64.decode(
      encryptedData,
    );

    /// It decrypts the data and returns the decrypted data in Uint8List format
    Uint8List decryptedBytes = gcmBlockCipherObj.process(
      encryptedDataBytes,
    );

    // Convert the decrypted data (Uint8List) to String format
    String decryptedData = utf8.decode(
      decryptedBytes,
    );

    print("decryptedData $decryptedData");

    return decryptedData;
  }
}
