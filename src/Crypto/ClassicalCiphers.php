<?php
namespace Crypto;

/**
 * Educational Classical Ciphers Implementation
 * WARNING: Classical ciphers do NOT provide modern cryptographic security.
 * Use AES-256-GCM for real security.
 */
class ClassicalCiphers {

    // 1. Caesar Cipher
    public static function caesarEncrypt(string $text, int $shift): string {
        $shift = ($shift % 26 + 26) % 26;
        $result = '';
        foreach (str_split($text) as $char) {
            if (ctype_upper($char)) {
                $result .= chr((ord($char) - 65 + $shift) % 26 + 65);
            } elseif (ctype_lower($char)) {
                $result .= chr((ord($char) - 97 + $shift) % 26 + 97);
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    public static function caesarDecrypt(string $text, int $shift): string {
        return self::caesarEncrypt($text, -$shift);
    }

    // 2. Simple Substitution Cipher
    public static function substitutionEncrypt(string $text, string $alphabetKey): string {
        $alphabetKey = strtoupper(preg_replace('/[^A-Z]/i', '', $alphabetKey));
        if (strlen($alphabetKey) !== 26) {
            throw new \Exception("Substitution key must contain exactly 26 unique letters.");
        }
        $stdUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $stdLower = "abcdefghijklmnopqrstuvwxyz";
        $keyLower = strtolower($alphabetKey);

        $result = '';
        foreach (str_split($text) as $char) {
            $posUpper = strpos($stdUpper, $char);
            $posLower = strpos($stdLower, $char);
            if ($posUpper !== false) {
                $result .= $alphabetKey[$posUpper];
            } elseif ($posLower !== false) {
                $result .= $keyLower[$posLower];
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    public static function substitutionDecrypt(string $text, string $alphabetKey): string {
        $alphabetKey = strtoupper(preg_replace('/[^A-Z]/i', '', $alphabetKey));
        if (strlen($alphabetKey) !== 26) {
            throw new \Exception("Substitution key must contain exactly 26 unique letters.");
        }
        $stdUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $stdLower = "abcdefghijklmnopqrstuvwxyz";
        $keyLower = strtolower($alphabetKey);

        $result = '';
        foreach (str_split($text) as $char) {
            $posUpper = strpos($alphabetKey, $char);
            $posLower = strpos($keyLower, $char);
            if ($posUpper !== false) {
                $result .= $stdUpper[$posUpper];
            } elseif ($posLower !== false) {
                $result .= $stdLower[$posLower];
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    // 3. Affine Cipher ( E(x) = (a*x + b) mod 26 )
    private static function modInverse(int $a, int $m): int {
        $a = ($a % $m + $m) % $m;
        for ($x = 1; $x < $m; $x++) {
            if (($a * $x) % $m == 1) return $x;
        }
        throw new \Exception("Key 'a' must be coprime to 26.");
    }

    public static function affineEncrypt(string $text, int $a, int $b): string {
        if (self::gcd($a, 26) !== 1) {
            throw new \Exception("Key 'a' ($a) is not coprime with 26.");
        }
        $result = '';
        foreach (str_split($text) as $char) {
            if (ctype_upper($char)) {
                $result .= chr((($a * (ord($char) - 65) + $b) % 26 + 26) % 26 + 65);
            } elseif (ctype_lower($char)) {
                $result .= chr((($a * (ord($char) - 97) + $b) % 26 + 26) % 26 + 97);
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    public static function affineDecrypt(string $text, int $a, int $b): string {
        $aInv = self::modInverse($a, 26);
        $result = '';
        foreach (str_split($text) as $char) {
            if (ctype_upper($char)) {
                $result .= chr((($aInv * (ord($char) - 65 - $b)) % 26 + 26) % 26 + 65);
            } elseif (ctype_lower($char)) {
                $result .= chr((($aInv * (ord($char) - 97 - $b)) % 26 + 26) % 26 + 97);
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    private static function gcd(int $a, int $b): int {
        return $b === 0 ? $a : self::gcd($b, $a % $b);
    }

    // 4. Vigenère Cipher
    public static function vigenereEncrypt(string $text, string $key): string {
        $key = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
        if (empty($key)) return $text;
        $keyLen = strlen($key);
        $kIdx = 0;
        $result = '';
        foreach (str_split($text) as $char) {
            if (ctype_alpha($char)) {
                $shift = ord($key[$kIdx % $keyLen]) - 65;
                $base = ctype_upper($char) ? 65 : 97;
                $result .= chr((ord($char) - $base + $shift) % 26 + $base);
                $kIdx++;
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    public static function vigenereDecrypt(string $text, string $key): string {
        $key = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
        if (empty($key)) return $text;
        $keyLen = strlen($key);
        $kIdx = 0;
        $result = '';
        foreach (str_split($text) as $char) {
            if (ctype_alpha($char)) {
                $shift = ord($key[$kIdx % $keyLen]) - 65;
                $base = ctype_upper($char) ? 65 : 97;
                $result .= chr((ord($char) - $base - $shift + 26) % 26 + $base);
                $kIdx++;
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    // 5. Autokey Cipher
    public static function autokeyEncrypt(string $text, string $key): string {
        $cleanText = strtoupper(preg_replace('/[^A-Z]/i', '', $text));
        $cleanKey = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
        if (empty($cleanKey)) return $text;
        
        $fullKey = $cleanKey . $cleanText;
        $result = '';
        $kIdx = 0;
        foreach (str_split($text) as $char) {
            if (ctype_alpha($char)) {
                $shift = ord($fullKey[$kIdx]) - 65;
                $base = ctype_upper($char) ? 65 : 97;
                $result .= chr((ord($char) - $base + $shift) % 26 + $base);
                $kIdx++;
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    public static function autokeyDecrypt(string $text, string $key): string {
        $cleanKey = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
        if (empty($cleanKey)) return $text;
        
        $result = '';
        $kStream = $cleanKey;
        $kIdx = 0;
        foreach (str_split($text) as $char) {
            if (ctype_alpha($char)) {
                $shift = ord($kStream[$kIdx]) - 65;
                $base = ctype_upper($char) ? 65 : 97;
                $decCharOrd = (ord($char) - $base - $shift + 26) % 26;
                $decChar = chr($decCharOrd + 65);
                $kStream .= $decChar;
                $result .= ctype_upper($char) ? $decChar : strtolower($decChar);
                $kIdx++;
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    // 6. Beaufort Cipher ( C = (K - P) mod 26 )
    public static function beaufortEncrypt(string $text, string $key): string {
        $key = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
        if (empty($key)) return $text;
        $keyLen = strlen($key);
        $kIdx = 0;
        $result = '';
        foreach (str_split($text) as $char) {
            if (ctype_alpha($char)) {
                $k = ord($key[$kIdx % $keyLen]) - 65;
                $p = ctype_upper($char) ? ord($char) - 65 : ord($char) - 97;
                $c = ($k - $p + 26) % 26;
                $base = ctype_upper($char) ? 65 : 97;
                $result .= chr($c + $base);
                $kIdx++;
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    public static function beaufortDecrypt(string $text, string $key): string {
        return self::beaufortEncrypt($text, $key);
    }

    // 7. Playfair Cipher
    public static function playfairEncrypt(string $text, string $key): string {
        $matrix = self::buildPlayfairMatrix($key);
        $clean = strtoupper(preg_replace('/[^A-Z]/i', '', str_replace('J', 'I', $text)));
        if (empty($clean)) return '';

        $digrams = [];
        for ($i = 0; $i < strlen($clean); $i++) {
            $ch1 = $clean[$i];
            $ch2 = ($i + 1 < strlen($clean)) ? $clean[$i + 1] : 'X';
            if ($ch1 === $ch2) {
                $digrams[] = [$ch1, 'X'];
            } else {
                $digrams[] = [$ch1, $ch2];
                $i++;
            }
        }

        $result = '';
        foreach ($digrams as [$c1, $c2]) {
            [$r1, $col1] = self::findPlayfairPos($matrix, $c1);
            [$r2, $col2] = self::findPlayfairPos($matrix, $c2);

            if ($r1 === $r2) {
                $result .= $matrix[$r1][($col1 + 1) % 5] . $matrix[$r2][($col2 + 1) % 5];
            } elseif ($col1 === $col2) {
                $result .= $matrix[($r1 + 1) % 5][$col1] . $matrix[($r2 + 1) % 5][$col2];
            } else {
                $result .= $matrix[$r1][$col2] . $matrix[$r2][$col1];
            }
        }
        return $result;
    }

    public static function playfairDecrypt(string $text, string $key): string {
        $matrix = self::buildPlayfairMatrix($key);
        $clean = strtoupper(preg_replace('/[^A-Z]/i', '', $text));
        if (strlen($clean) % 2 !== 0) return $text;

        $result = '';
        for ($i = 0; $i < strlen($clean); $i += 2) {
            $c1 = $clean[$i];
            $c2 = $clean[$i + 1];
            [$r1, $col1] = self::findPlayfairPos($matrix, $c1);
            [$r2, $col2] = self::findPlayfairPos($matrix, $c2);

            if ($r1 === $r2) {
                $result .= $matrix[$r1][($col1 + 4) % 5] . $matrix[$r2][($col2 + 4) % 5];
            } elseif ($col1 === $col2) {
                $result .= $matrix[($r1 + 4) % 5][$col1] . $matrix[($r2 + 4) % 5][$col2];
            } else {
                $result .= $matrix[$r1][$col2] . $matrix[$r2][$col1];
            }
        }
        return $result;
    }

    private static function buildPlayfairMatrix(string $key): array {
        $cleanKey = strtoupper(preg_replace('/[^A-Z]/i', '', str_replace('J', 'I', $key)));
        $alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
        $combined = $cleanKey . $alpha;
        $used = [];
        $matrix = [];
        $r = 0; $c = 0;

        for ($i = 0; $i < strlen($combined); $i++) {
            $ch = $combined[$i];
            if (!isset($used[$ch])) {
                $used[$ch] = true;
                $matrix[$r][$c] = $ch;
                $c++;
                if ($c === 5) {
                    $c = 0; $r++;
                }
            }
        }
        return $matrix;
    }

    private static function findPlayfairPos(array $matrix, string $ch): array {
        for ($r = 0; $r < 5; $r++) {
            for ($c = 0; $c < 5; $c++) {
                if ($matrix[$r][$c] === $ch) return [$r, $c];
            }
        }
        return [0, 0];
    }

    // 8. Hill Cipher (2x2 Matrix)
    public static function hillEncrypt(string $text, array $key2x2): string {
        $clean = strtoupper(preg_replace('/[^A-Z]/i', '', $text));
        if (strlen($clean) % 2 !== 0) $clean .= 'X';

        $result = '';
        for ($i = 0; $i < strlen($clean); $i += 2) {
            $p1 = ord($clean[$i]) - 65;
            $p2 = ord($clean[$i + 1]) - 65;
            $c1 = ($key2x2[0][0] * $p1 + $key2x2[0][1] * $p2) % 26;
            $c2 = ($key2x2[1][0] * $p1 + $key2x2[1][1] * $p2) % 26;
            $result .= chr($c1 + 65) . chr($c2 + 65);
        }
        return $result;
    }

    public static function hillDecrypt(string $text, array $key2x2): string {
        $clean = strtoupper(preg_replace('/[^A-Z]/i', '', $text));
        if (strlen($clean) % 2 !== 0) return $text;

        $det = ($key2x2[0][0] * $key2x2[1][1] - $key2x2[0][1] * $key2x2[1][0]) % 26;
        $det = ($det + 26) % 26;
        $detInv = self::modInverse($det, 26);

        $kInv = [
            [($key2x2[1][1] * $detInv) % 26, ((-$key2x2[0][1] * $detInv) % 26 + 26) % 26],
            [((-$key2x2[1][0] * $detInv) % 26 + 26) % 26, ($key2x2[0][0] * $detInv) % 26]
        ];

        $result = '';
        for ($i = 0; $i < strlen($clean); $i += 2) {
            $c1 = ord($clean[$i]) - 65;
            $c2 = ord($clean[$i + 1]) - 65;
            $p1 = ($kInv[0][0] * $c1 + $kInv[0][1] * $c2) % 26;
            $p2 = ($kInv[1][0] * $c1 + $kInv[1][1] * $c2) % 26;
            $result .= chr($p1 + 65) . chr($p2 + 65);
        }
        return $result;
    }

    // 9. Rail Fence Cipher
    public static function railFenceEncrypt(string $text, int $rails): string {
        if ($rails <= 1) return $text;
        $fence = array_fill(0, $rails, []);
        $rail = 0;
        $direction = 1;

        foreach (str_split($text) as $char) {
            $fence[$rail][] = $char;
            $rail += $direction;
            if ($rail === 0 || $rail === $rails - 1) {
                $direction = -$direction;
            }
        }

        $result = '';
        foreach ($fence as $row) {
            $result .= implode('', $row);
        }
        return $result;
    }

    public static function railFenceDecrypt(string $text, int $rails): string {
        if ($rails <= 1) return $text;
        $len = strlen($text);
        $mark = array_fill(0, $rails, array_fill(0, $len, false));
        
        $rail = 0;
        $direction = 1;
        for ($i = 0; $i < $len; $i++) {
            $mark[$rail][$i] = true;
            $rail += $direction;
            if ($rail === 0 || $rail === $rails - 1) {
                $direction = -$direction;
            }
        }

        $idx = 0;
        $fence = array_fill(0, $rails, array_fill(0, $len, ''));
        for ($r = 0; $r < $rails; $r++) {
            for ($c = 0; $c < $len; $c++) {
                if ($mark[$r][$c] && $idx < $len) {
                    $fence[$r][$c] = $text[$idx++];
                }
            }
        }

        $result = '';
        $rail = 0;
        $direction = 1;
        for ($i = 0; $i < $len; $i++) {
            $result .= $fence[$rail][$i];
            $rail += $direction;
            if ($rail === 0 || $rail === $rails - 1) {
                $direction = -$direction;
            }
        }
        return $result;
    }

    // 10. Columnar Transposition Cipher
    public static function columnarEncrypt(string $text, string $key): string {
        $cleanKey = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
        if (empty($cleanKey)) return $text;

        $numCols = strlen($cleanKey);
        $rows = (int)ceil(strlen($text) / $numCols);
        
        $padded = str_pad($text, $rows * $numCols, 'X');
        
        $keyArr = str_split($cleanKey);
        $cols = [];
        for ($i = 0; $i < $numCols; $i++) {
            $cols[] = ['char' => $keyArr[$i], 'index' => $i];
        }
        usort($cols, function($a, $b) {
            return strcmp($a['char'], $b['char']);
        });

        $result = '';
        foreach ($cols as $cData) {
            $colIdx = $cData['index'];
            for ($r = 0; $r < $rows; $r++) {
                $result .= $padded[$r * $numCols + $colIdx];
            }
        }
        return $result;
    }

    public static function columnarDecrypt(string $text, string $key): string {
        $cleanKey = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
        if (empty($cleanKey)) return $text;

        $numCols = strlen($cleanKey);
        $len = strlen($text);
        $rows = (int)ceil($len / $numCols);

        $keyArr = str_split($cleanKey);
        $cols = [];
        for ($i = 0; $i < $numCols; $i++) {
            $cols[] = ['char' => $keyArr[$i], 'index' => $i];
        }
        usort($cols, function($a, $b) {
            return strcmp($a['char'], $b['char']);
        });

        $grid = array_fill(0, $rows, array_fill(0, $numCols, ''));
        $idx = 0;
        foreach ($cols as $cData) {
            $colIdx = $cData['index'];
            for ($r = 0; $r < $rows; $r++) {
                if ($idx < $len) {
                    $grid[$r][$colIdx] = $text[$idx++];
                }
            }
        }

        $result = '';
        for ($r = 0; $r < $rows; $r++) {
            for ($c = 0; $c < $numCols; $c++) {
                $result .= $grid[$r][$c];
            }
        }
        return $result;
    }

    // 11. Double Transposition Cipher
    public static function doubleTranspositionEncrypt(string $text, string $key1, string $key2): string {
        $pass1 = self::columnarEncrypt($text, $key1);
        return self::columnarEncrypt($pass1, $key2);
    }

    public static function doubleTranspositionDecrypt(string $text, string $key1, string $key2): string {
        $pass1 = self::columnarDecrypt($text, $key2);
        return self::columnarDecrypt($pass1, $key1);
    }
}
