<?php
namespace Security;

use Database\Database;
use PDO;

class SecurityQuestions {

    /**
     * Get 5 random distinct active questions from the pool of 500
     */
    public static function getRandomFiveQuestions(): array {
        $db = Database::getInstance();
        $stmt = $db->query("SELECT id, question_text FROM security_questions WHERE active = 1 ORDER BY RANDOM() LIMIT 5");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Store 5 question-answer pairs for a newly registered user
     * $answers = [ question_id => answer_text ]
     */
    public static function assignUserQuestions(int $userId, array $answers): bool {
        if (count($answers) !== 5) {
            return false;
        }

        $db = Database::getInstance();
        $inTx = $db->inTransaction();

        if (!$inTx) {
            $db->beginTransaction();
        }

        try {
            $stmt = $db->prepare("INSERT INTO user_security_questions (user_id, question_id, answer_hash) VALUES (:user_id, :question_id, :answer_hash)");
            
            foreach ($answers as $qId => $ansText) {
                $cleanAns = mb_strtolower(trim((string)$ansText), 'UTF-8');
                $hash = password_hash($cleanAns, PASSWORD_DEFAULT);
                $stmt->execute([
                    ':user_id' => $userId,
                    ':question_id' => (int)$qId,
                    ':answer_hash' => $hash
                ]);
            }

            if (!$inTx) {
                $db->commit();
            }
            return true;
        } catch (\Exception $e) {
            if (!$inTx && $db->inTransaction()) {
                $db->rollBack();
            }
            return false;
        }
    }

    /**
     * Retrieve a user's PERMANENT 5 security questions
     * Randomized ONLY in display order for reset presentation
     */
    public static function getUserQuestionsForReset(int $userId): array {
        $db = Database::getInstance();
        $stmt = $db->prepare("
            SELECT sq.id, sq.question_text
            FROM user_security_questions usq
            JOIN security_questions sq ON usq.question_id = sq.id
            WHERE usq.user_id = :user_id
        ");
        $stmt->execute([':user_id' => $userId]);
        $questions = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Shuffle ONLY the display order of the exact 5 assigned questions
        shuffle($questions);
        return $questions;
    }

    /**
     * Verify user's submitted 5 answers against saved hashes
     * $submittedAnswers = [ question_id => submitted_answer_text ]
     * Returns true ONLY if ALL 5 are correct. Returns false if ANY is wrong.
     */
    public static function verifyUserAnswers(int $userId, array $submittedAnswers): bool {
        if (count($submittedAnswers) !== 5) {
            return false;
        }

        $db = Database::getInstance();
        $stmt = $db->prepare("
            SELECT question_id, answer_hash
            FROM user_security_questions
            WHERE user_id = :user_id
        ");
        $stmt->execute([':user_id' => $userId]);
        $stored = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (count($stored) !== 5) {
            return false;
        }

        $storedMap = [];
        foreach ($stored as $row) {
            $storedMap[$row['question_id']] = $row['answer_hash'];
        }

        $allCorrect = true;

        foreach ($submittedAnswers as $qId => $subAns) {
            if (!isset($storedMap[$qId])) {
                $allCorrect = false;
                break;
            }
            $cleanSub = mb_strtolower(trim((string)$subAns), 'UTF-8');
            if (!password_verify($cleanSub, $storedMap[$qId])) {
                $allCorrect = false;
            }
        }

        return $allCorrect;
    }
}
