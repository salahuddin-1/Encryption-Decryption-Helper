import 'package:encryption_decryption_helper/encryption_utility/des3/des3_encryption_utility.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    testEncryptionAndDecryption();

    return MaterialApp(
      title: 'Encryption Decryption Helper',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Encryption Decryption Helper"),
      ),
      body: const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text(
              'YEncryption Decryption Helper',
            ),
          ],
        ),
      ),
    );
  }
}

void testEncryptionAndDecryption() {
  String cardNo = "123456";

  String encryptedCardNo = DES3EncryptionUtility.encrypt(
    cardNumber: cardNo,
  );

  print("encryptedCardNo $encryptedCardNo");

  String decryptedCardNo = DES3EncryptionUtility.decrypt(
    cardNo: encryptedCardNo,
  );

  print("decryptedCardNo $decryptedCardNo");
}
