<?php
use Crypto\ClassicalCiphers;

// 1. Caesar
$caesarEnc = ClassicalCiphers::caesarEncrypt("HELLO WORLD", 3);
$caesarDec = ClassicalCiphers::caesarDecrypt($caesarEnc, 3);
assertTest($caesarEnc === "KHOOR ZRUOG" && $caesarDec === "HELLO WORLD", "Classical Ciphers: Caesar Cipher encrypt/decrypt roundtrip");

// 2. Substitution
$key = "QWERTYUIOPASDFGHJKLZXCVBNM";
$subEnc = ClassicalCiphers::substitutionEncrypt("HELLO", $key);
$subDec = ClassicalCiphers::substitutionDecrypt($subEnc, $key);
assertTest($subDec === "HELLO", "Classical Ciphers: Simple Substitution Cipher roundtrip");

// 3. Affine
$affEnc = ClassicalCiphers::affineEncrypt("HELLO", 5, 8);
$affDec = ClassicalCiphers::affineDecrypt($affEnc, 5, 8);
assertTest($affDec === "HELLO", "Classical Ciphers: Affine Cipher roundtrip");

// 4. Vigenère
$vigEnc = ClassicalCiphers::vigenereEncrypt("ATTACKATDAWN", "LEMON");
$vigDec = ClassicalCiphers::vigenereDecrypt($vigEnc, "LEMON");
assertTest($vigDec === "ATTACKATDAWN", "Classical Ciphers: Vigenère Cipher roundtrip");

// 5. Autokey
$autoEnc = ClassicalCiphers::autokeyEncrypt("MEETATMIDNIGHT", "QUEEN");
$autoDec = ClassicalCiphers::autokeyDecrypt($autoEnc, "QUEEN");
assertTest(strtoupper(preg_replace('/[^A-Z]/', '', $autoDec)) === "MEETATMIDNIGHT", "Classical Ciphers: Autokey Cipher roundtrip");

// 6. Beaufort
$beauEnc = ClassicalCiphers::beaufortEncrypt("SECRET", "KEY");
$beauDec = ClassicalCiphers::beaufortDecrypt($beauEnc, "KEY");
assertTest($beauDec === "SECRET", "Classical Ciphers: Beaufort Cipher roundtrip");

// 7. Rail Fence
$railEnc = ClassicalCiphers::railFenceEncrypt("DEFENDTHEEASTWALL", 3);
$railDec = ClassicalCiphers::railFenceDecrypt($railEnc, 3);
assertTest($railDec === "DEFENDTHEEASTWALL", "Classical Ciphers: Rail Fence Cipher roundtrip");

// 8. Columnar Transposition
$colEnc = ClassicalCiphers::columnarEncrypt("ATTACKATDAWN", "SECRET");
assertTest(!empty($colEnc), "Classical Ciphers: Columnar Transposition produces cipher text");

// 9. Double Transposition
$dblEnc = ClassicalCiphers::doubleTranspositionEncrypt("TOPSECRETDATA", "KEYONE", "KEYTWO");
assertTest(!empty($dblEnc), "Classical Ciphers: Double Transposition produces cipher text");
