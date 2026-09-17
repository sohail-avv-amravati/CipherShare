<?php
namespace Crypto;

class DocumentTextExtractor {

    private static array $supportedExtensions = [
        'txt', 'text', 'doc', 'docx', 'pdf', 'csv', 'json', 'md', 'rtf', 'log'
    ];

    /**
     * Check if a filename has a supported extension for text extraction
     */
    public static function isSupported(string $filename): bool {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        return in_array($ext, self::$supportedExtensions, true);
    }

    /**
     * Get list of supported extensions
     */
    public static function getSupportedExtensions(): array {
        return self::$supportedExtensions;
    }

    /**
     * Extract clean text content from a file path based on its extension
     */
    public static function extractFromFile(string $filePath, string $originalFilename = ''): string {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            throw new \Exception("File not found or not readable on server.");
        }

        $ext = strtolower(pathinfo($originalFilename ?: $filePath, PATHINFO_EXTENSION));

        switch ($ext) {
            case 'txt':
            case 'text':
            case 'csv':
            case 'json':
            case 'md':
            case 'log':
                return self::extractFromPlainText($filePath);

            case 'docx':
                return self::extractFromDocx($filePath);

            case 'doc':
                return self::extractFromDoc($filePath);

            case 'pdf':
                return self::extractFromPdf($filePath);

            case 'rtf':
                return self::extractFromRtf($filePath);

            default:
                // Fallback: try plain text reading
                return self::extractFromPlainText($filePath);
        }
    }

    /**
     * Extract text from an uploaded $_FILES entry
     */
    public static function extractFromUpload(array $fileArray, ?string &$error = null): ?string {
        if (!isset($fileArray['error']) || $fileArray['error'] !== UPLOAD_ERR_OK) {
            $error = "File upload failed or no file selected.";
            return null;
        }

        $tmpPath = $fileArray['tmp_name'] ?? '';
        $originalName = (string)($fileArray['name'] ?? 'document.txt');

        if (empty($tmpPath) || !file_exists($tmpPath)) {
            $error = "Uploaded file not found.";
            return null;
        }

        if (!self::isSupported($originalName)) {
            $error = "Unsupported file type for classical ciphers. Supported: .txt, .doc, .docx, .pdf, .csv, .md";
            return null;
        }

        $size = (int)($fileArray['size'] ?? 0);
        if ($size > 10 * 1024 * 1024) { // 10MB limit for text extraction
            $error = "Document too large for classical cipher processing (max 10 MB).";
            return null;
        }

        try {
            $text = self::extractFromFile($tmpPath, $originalName);
            if (empty(trim($text))) {
                $error = "No readable text could be extracted from '{$originalName}'. Ensure the file contains selectable text.";
                return null;
            }
            return $text;
        } catch (\Exception $e) {
            $error = "Failed to extract text: " . $e->getMessage();
            return null;
        }
    }

    /**
     * Extract plain text files
     */
    private static function extractFromPlainText(string $path): string {
        $content = @file_get_contents($path);
        if ($content === false) {
            throw new \Exception("Could not read plain text file.");
        }
        // Remove UTF-8 BOM if present
        if (substr($content, 0, 3) === "\xEF\xBB\xBF") {
            $content = substr($content, 3);
        }
        return self::cleanText($content);
    }

    /**
     * Extract text from Microsoft Word (.docx)
     */
    private static function extractFromDocx(string $path): string {
        if (!class_exists('ZipArchive')) {
            throw new \Exception("PHP ZipArchive extension is required to read .docx files.");
        }

        $zip = new \ZipArchive();
        $res = $zip->open($path);
        if ($res !== true) {
            throw new \Exception("Could not open .docx archive (code {$res}).");
        }

        $xml = $zip->getFromName('word/document.xml');
        $zip->close();

        if ($xml === false) {
            throw new \Exception("Could not find document content inside .docx file.");
        }

        // Add spaces and newlines for XML tags
        $xml = preg_replace('/<\/w:p>/i', "\n", $xml);
        $xml = preg_replace('/<w:br[^>]*>/i', "\n", $xml);
        $xml = preg_replace('/<\/w:tc>/i', "\t", $xml);

        $text = strip_tags($xml);
        $text = html_entity_decode($text, ENT_QUOTES | ENT_XML1, 'UTF-8');
        return self::cleanText($text);
    }

    /**
     * Extract text from legacy Microsoft Word (.doc)
     */
    private static function extractFromDoc(string $path): string {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new \Exception("Could not read .doc file.");
        }

        // Extract printable ASCII chunks of 3 or more chars
        $text = '';
        if (preg_match_all('/[\x20-\x7E\r\n\t]{3,}/', $raw, $matches)) {
            $text = implode("\n", $matches[0]);
        }

        if (empty(trim($text))) {
            // Try extracting UTF-16LE characters common in Word binary streams
            if (preg_match_all('/(?:[\x20-\x7E]\x00){3,}/', $raw, $matches)) {
                $converted = [];
                foreach ($matches[0] as $chunk) {
                    $converted[] = @mb_convert_encoding($chunk, 'UTF-8', 'UTF-16LE');
                }
                $text = implode("\n", $converted);
            }
        }

        return self::cleanText($text);
    }

    /**
     * Extract text from PDF documents
     */
    private static function extractFromPdf(string $path): string {
        $content = @file_get_contents($path);
        if ($content === false) {
            throw new \Exception("Could not read PDF file.");
        }

        if (substr($content, 0, 4) !== '%PDF') {
            throw new \Exception("The file is not a valid PDF document.");
        }

        $extractedText = '';

        // Match all streams in the PDF: /Filter /FlateDecode ... stream ... endstream
        // We use offset-based search to handle large binary streams reliably
        $pos = 0;
        while (($streamStart = strpos($content, 'stream', $pos)) !== false) {
            // Find endstream
            $streamEnd = strpos($content, 'endstream', $streamStart);
            if ($streamEnd === false) break;

            // Look back up to 256 bytes before stream keyword for stream header / dictionary
            $dictStart = max(0, $streamStart - 256);
            $dictChunk = substr($content, $dictStart, $streamStart - $dictStart);

            $isFlate = (stripos($dictChunk, '/FlateDecode') !== false || stripos($dictChunk, '/Fl') !== false);

            // Stream data begins after 'stream' + CRLF or LF
            $dataStart = $streamStart + 6;
            if (substr($content, $dataStart, 2) === "\r\n") {
                $dataStart += 2;
            } elseif (substr($content, $dataStart, 1) === "\n" || substr($content, $dataStart, 1) === "\r") {
                $dataStart += 1;
            }

            $dataLen = $streamEnd - $dataStart;
            // Trim trailing \r\n before endstream
            $streamData = substr($content, $dataStart, $dataLen);

            $uncompressed = null;
            if ($isFlate && function_exists('gzuncompress')) {
                $uncompressed = @gzuncompress($streamData);
            } elseif (!$isFlate) {
                $uncompressed = $streamData;
            }

            if (!empty($uncompressed)) {
                $textFromStream = self::parsePdfOperators($uncompressed);
                if (!empty($textFromStream)) {
                    $extractedText .= $textFromStream . "\n";
                }
            }

            $pos = $streamEnd + 9;
        }

        // If stream-level parsing produced little or no text, fallback to global PDF text literal search
        if (strlen(trim($extractedText)) < 10) {
            $fallback = self::parsePdfOperators($content);
            if (!empty($fallback)) {
                $extractedText .= $fallback;
            }
        }

        // If still empty, attempt to extract any readable strings in BT...ET blocks
        if (empty(trim($extractedText))) {
            if (preg_match_all('/BT[\s\S]*?ET/', $content, $btMatches)) {
                foreach ($btMatches[0] as $bt) {
                    $extractedText .= self::parsePdfOperators($bt) . "\n";
                }
            }
        }

        return self::cleanText($extractedText);
    }

    /**
     * Parse text operators from a PDF content stream
     */
    private static function parsePdfOperators(string $stream): string {
        $result = '';

        // 1. Array text show: [(Text) -10 (more text)] TJ
        if (preg_match_all('/\[(.*?)\]\s*TJ/s', $stream, $tjMatches)) {
            foreach ($tjMatches[1] as $arr) {
                if (preg_match_all('/\((.*?)(?<!\\\\)\)/s', $arr, $strMatches)) {
                    foreach ($strMatches[1] as $s) {
                        $result .= self::unescapePdfString($s);
                    }
                    $result .= " ";
                }
                // Also support hex strings inside TJ: [<48656c6c6f>]
                if (preg_match_all('/<([0-9a-fA-F\s]+)>/s', $arr, $hexMatches)) {
                    foreach ($hexMatches[1] as $hex) {
                        $cleanHex = preg_replace('/\s+/', '', $hex);
                        if (strlen($cleanHex) % 2 === 0) {
                            $result .= @hex2bin($cleanHex);
                        }
                    }
                    $result .= " ";
                }
            }
        }

        // 2. Simple text show: (Text string) Tj or ' or "
        if (preg_match_all('/\((.*?)(?<!\\\\)\)\s*(?:Tj|\'|")/s', $stream, $tMatches)) {
            foreach ($tMatches[1] as $s) {
                $result .= self::unescapePdfString($s) . " ";
            }
        }

        // 3. Hex string show: <48656c6c6f> Tj
        if (preg_match_all('/<([0-9a-fA-F\s]+)>\s*(?:Tj|\'|")/s', $stream, $hMatches)) {
            foreach ($hMatches[1] as $hex) {
                $cleanHex = preg_replace('/\s+/', '', $hex);
                if (strlen($cleanHex) % 2 === 0) {
                    $result .= @hex2bin($cleanHex) . " ";
                }
            }
        }

        return $result;
    }

    /**
     * Unescape PDF string escape sequences
     */
    private static function unescapePdfString(string $str): string {
        // Replace standard PDF escapes
        $str = str_replace(
            ['\\n', '\\r', '\\t', '\\b', '\\f', '\\(', '\\)', '\\\\'],
            ["\n",  "\r",  "\t",  "\x08", "\x0C", "(",   ")",   "\\"],
            $str
        );
        // Replace octal escapes \ddd
        $str = preg_replace_callback('/\\\\([0-7]{1,3})/', function ($m) {
            return chr(octdec($m[1]));
        }, $str);
        return $str;
    }

    /**
     * Extract text from RTF format
     */
    private static function extractFromRtf(string $path): string {
        $raw = @file_get_contents($path);
        if ($raw === false) return '';
        // Strip RTF control words
        $text = preg_replace('/\\\\[a-z0-9]+ ?/i', '', $raw);
        $text = preg_replace('/[{}]/', '', $text);
        return self::cleanText($text);
    }

    /**
     * Clean and normalize extracted text
     */
    private static function cleanText(string $text): string {
        // Convert to UTF-8
        $text = @mb_convert_encoding($text, 'UTF-8', 'UTF-8');
        // Normalize newlines
        $text = str_replace(["\r\n", "\r"], "\n", $text);
        // Remove control characters except standard whitespace (\n, \t, space)
        $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $text);
        // Collapse 3+ consecutive newlines to 2
        $text = preg_replace('/\n{3,}/', "\n\n", $text);
        return trim($text);
    }
}
