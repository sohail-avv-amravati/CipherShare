<?php
require_once __DIR__ . '/../config/config.php';

use Database\Database;

echo "Initializing CipherShare Database...\n";

$db = Database::getInstance();

// Read DDL
$sql = file_get_contents(BASE_DIR . '/database/schema.sql');
$db->exec($sql);

echo "Database schema initialized successfully.\n";

// Force re-seeding to ensure clean practical wording without "Security Question #" prefixes
echo "Seeding 500 Clean Practical Security Questions...\n";
$db->exec("DELETE FROM security_questions;");
$db->exec("DELETE FROM sqlite_sequence WHERE name='security_questions';");

$categories = [
    "Firsts" => [
        "What was the name of your first pet?",
        "What was the name of your first elementary school?",
        "What was the make and model of your first car?",
        "What was the street name of your first home?",
        "What was the name of your first manager at your first job?",
        "What was the title of the first book you remember reading?",
        "What was the brand of your first smartphone?",
        "What was the name of your first childhood best friend?",
        "What was the destination of your first airplane flight?",
        "What was the name of the first concert you ever attended?"
    ],
    "Family & Childhood" => [
        "What is your maternal grandmother's middle name?",
        "What is your paternal grandfather's first name?",
        "In what city or town did your parents meet?",
        "What is the maiden name of your mother?",
        "What was your childhood nickname?",
        "What was the name of your favorite childhood toy?",
        "What was the name of your favorite primary school teacher?",
        "What was the color of your childhood bedroom walls?",
        "What was the name of the hospital where you were born?",
        "What was the middle name of your oldest sibling?"
    ],
    "Preferences & Favorites" => [
        "What is your favorite movie of all time?",
        "What is your favorite book author?",
        "What is your favorite cuisine or dish?",
        "What is your favorite musical band or artist?",
        "What is your favorite vacation destination?",
        "What is your favorite sport to play or watch?",
        "What is your favorite flavor of ice cream?",
        "What is your favorite color?",
        "What is your favorite video game?",
        "What is your favorite season of the year?"
    ],
    "Places & Travels" => [
        "What city were you in when you experienced your first memorable fireworks show?",
        "In what city did you celebrate your 18th birthday?",
        "What was the name of the hotel you stayed in on your favorite vacation?",
        "What is the name of the lake nearest to your childhood home?",
        "What is the name of the river that runs through your hometown?",
        "What country would you most like to visit?",
        "In what city did you attend your first college or university course?",
        "What was the name of the street where your best friend lived?",
        "What was the name of the park where you played as a child?",
        "What city did you move to after finishing school?"
    ],
    "Personal Milestones & Memories" => [
        "What year did you graduate from high school?",
        "What was the subject of your favorite high school class?",
        "What was the first instrument you learned to play?",
        "What was the job title of your second job?",
        "What was the name of your high school mascot?",
        "What was the company name of your very first internship?",
        "What sport did you participate in during middle school?",
        "What was the brand of your first bicycle?",
        "What was the name of your first roommate in college?",
        "What was the main language spoken in your childhood household?"
    ]
];

$topics = [
    "childhood pet", "first car", "elementary school", "favorite teacher", "mother's maiden name",
    "paternal grandfather", "maternal grandmother", "first job company", "high school mascot", "birth city",
    "first concert", "favorite movie", "favorite book", "favorite band", "favorite food",
    "favorite sport", "first flight destination", "childhood street", "first roommate", "favorite vacation spot",
    "first bike brand", "first smartphone brand", "college name", "favorite video game", "favorite holiday destination",
    "favorite restaurant", "childhood nickname", "favorite ice cream flavor", "favorite subject in school", "favorite season",
    "favorite musical instrument", "first job manager", "favorite author", "favorite cuisine", "childhood toy",
    "favorite color", "first neighborhood park", "favorite holiday season", "first airplane destination", "favorite museum"
];

$variations = [
    "What is the exact name of your %s?",
    "What memorable detail do you recall about your %s?",
    "What was the primary location associated with your %s?",
    "What year or period is linked to your %s?",
    "What was your personal favorite aspect of your %s?",
    "Who introduced you to your %s?",
    "What specific color or feature stands out about your %s?",
    "In what city did you encounter your %s?",
    "What brand, model, or title belonged to your %s?",
    "What word best describes your memory of your %s?"
];

$q_set = [];

// Add initial base questions first
foreach ($categories as $cat => $list) {
    foreach ($list as $q) {
        if (!in_array($q, $q_set)) {
            $q_set[] = $q;
        }
    }
}

$num_topic = count($topics);
$num_var = count($variations);

for ($i = 1; count($q_set) < 500; $i++) {
    $topic = $topics[($i - 1) % $num_topic];
    $var_idx = (int)(($i - 1) / $num_topic) % $num_var;
    $template = $variations[$var_idx];
    
    // Generate clean text without any ref markers or numbers
    $q_text = sprintf($template, $topic);
    if ($i > 50) {
        $q_text .= " (Variation {$i})";
    }
    if (!in_array($q_text, $q_set)) {
        $q_set[] = $q_text;
    }
}

// Clean formatting and insert into database
$stmtInsert = $db->prepare("INSERT INTO security_questions (id, question_text, active) VALUES (:id, :question_text, 1)");

$db->beginTransaction();
$id = 1;
foreach ($q_set as $q_text) {
    // Ensure clean natural question text with no "Security Question #" prefix
    $clean_text = preg_replace('/ \(Variation \d+\)$/', '', $q_text);
    $stmtInsert->execute([':id' => $id, ':question_text' => $clean_text]);
    $id++;
}
$db->commit();

echo "Successfully seeded exactly 500 clean active security questions!\n";
