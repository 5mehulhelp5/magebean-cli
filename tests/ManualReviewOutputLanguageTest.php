<?php

declare(strict_types=1);

function assertManualEnglish(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

foreach (['MB-C13.json', 'MB-C15.json', 'MB-C16.json'] as $file) {
    $control = json_decode(
        (string)file_get_contents(__DIR__ . '/../src/Rules/controls/' . $file),
        true,
        512,
        JSON_THROW_ON_ERROR
    );
    foreach ($control['rules'] ?? [] as $rule) {
        $review = (string)($rule['checks'][0]['args']['review'] ?? '');
        assertManualEnglish($review !== '', ($rule['id'] ?? $file) . ' is missing review guidance');
        assertManualEnglish(
            !str_contains($review, 'Review the application design, implementation, configuration, tests, and supporting evidence to verify:'),
            ($rule['id'] ?? $file) . ' still uses the verbose review prefix'
        );
        assertManualEnglish(str_contains($review, 'MANDATORY HUMAN ASSESSMENT'), ($rule['id'] ?? $file) . ' lacks mandatory-assessment wording');
        assertManualEnglish(str_contains($review, 'Magebean CLI cannot determine or attest compliance'), ($rule['id'] ?? $file) . ' lacks CLI limitation disclaimer');
        assertManualEnglish(
            preg_match('/[^\x09\x0A\x0D\x20-\x7E]/', $review) !== 1,
            ($rule['id'] ?? $file) . ' review guidance contains non-English/non-ASCII text: ' . $review
        );
    }
}

echo "ManualReviewOutputLanguageTest: PASS\n";
