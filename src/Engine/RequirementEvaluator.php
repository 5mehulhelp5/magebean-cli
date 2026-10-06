<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Each source preserves its all/any alternatives; separate source obligations use AND. */
final class RequirementEvaluator
{
    public static function evaluate(array $args, callable $evaluate): CheckResult
    {
        $observations = []; $outcomes = []; $failure = ''; $unknown = ''; $manual = ''; $deadline = false; $incomplete = false;
        foreach ($args['groups'] ?? [] as $group) {
            $results = []; $details = [];
            if (!empty($group['missing']) || empty($group['checks'])) {
                $results[] = CheckOutcome::Unknown;
                $details[] = ['check' => '', 'status' => 'UNKNOWN', 'message' => 'Required legacy evidence is unavailable.'];
            } else {
                if (!in_array($group['op'] ?? 'all', ['all', 'any'], true)) throw new \RuntimeException('Unsupported requirement evidence operator.');
                foreach ($group['checks'] as $check) {
                    $name = (string)($check['name'] ?? '');
                    if ($name === 'requirement_assessment') throw new \RuntimeException('Recursive requirement evidence is prohibited.');
                    $result = $evaluate($name, $check['args'] ?? []);
                    $deadline = $deadline || $result->reasonCode === 'SCAN_DEADLINE_EXCEEDED';
                    $results[] = $result->outcome;
                    $details[] = ['check' => $name, 'status' => $result->outcome->value, 'message' => $result->message, 'evidence' => $result->evidence];
                    if (($group['op'] ?? 'all') === 'any' && $result->outcome === CheckOutcome::Pass) break;
                }
            }
            $outcome = self::combine($results, ($group['op'] ?? 'all') === 'any');
            $incomplete = $incomplete || ($outcome !== CheckOutcome::Pass && in_array(CheckOutcome::Unknown, $results, true));
            $outcomes[] = $outcome;
            $observations[] = ['legacy_rule_id' => (string)$group['id'], 'operator' => $group['op'] ?? 'all', 'status' => $outcome->value, 'checks' => $details];
            foreach ($details as $detail) {
                if ($outcome === CheckOutcome::Fail && ($detail['status'] ?? '') === 'FAIL' && $failure === '') $failure = (string)$detail['message'];
                if ($outcome === CheckOutcome::Unknown && ($detail['status'] ?? '') === 'UNKNOWN' && $unknown === '') $unknown = (string)$detail['message'];
                if ($outcome === CheckOutcome::ManualReview && ($detail['status'] ?? '') === 'MANUAL_REVIEW' && $manual === '') $manual = (string)$detail['message'];
            }
        }
        $coverage = (string)($args['coverage'] ?? 'NOT_YET_COVERED');
        $evidence = ['requirement' => $args['requirement'] ?? [], 'assessment_level' => $args['assessment_level'] ?? null, 'coverage' => $coverage, 'groups' => $observations];
        if ($outcomes === []) return CheckResult::of(CheckOutcome::Unknown, '[UNKNOWN] No implementation evidence for this requirement.', $evidence, 'REQUIREMENT_COVERAGE_GAP');
        $outcome = self::combine($outcomes, false);
        // Legacy partial detectors are signals, not proof of a complete normative violation.
        if ($outcome === CheckOutcome::Fail && $coverage !== 'AUTOMATED') {
            if ($incomplete) return CheckResult::of(CheckOutcome::Unknown, '[UNKNOWN] Requirement evidence is incomplete; failing technical signals need review.', $evidence, $deadline ? 'SCAN_DEADLINE_EXCEEDED' : 'REQUIREMENT_EVIDENCE_INCOMPLETE');
            return CheckResult::of(CheckOutcome::ManualReview, 'Failing technical evidence requires independent confirmation against the requirement: ' . preg_replace('/^\[(UNKNOWN|MANUAL_REVIEW)\]\s*/', '', $failure), $evidence, 'REQUIREMENT_FAILURE_CONFIRMATION');
        }
        if ($outcome === CheckOutcome::Fail) return CheckResult::of($outcome, preg_replace('/^\[(UNKNOWN|MANUAL_REVIEW)\]\s*/', '', $failure) ?: 'A required evidence condition failed.', $evidence);
        if ($outcome === CheckOutcome::Unknown) return CheckResult::of($outcome, '[UNKNOWN] ' . preg_replace('/^\[(UNKNOWN|MANUAL_REVIEW)\]\s*/', '', $unknown), $evidence, $deadline ? 'SCAN_DEADLINE_EXCEEDED' : 'REQUIREMENT_EVIDENCE_INCOMPLETE');
        if ($outcome === CheckOutcome::ManualReview || $coverage !== 'AUTOMATED') {
            $message = preg_replace('/^\[MANUAL_REVIEW\]\s*/', '', $manual) ?: 'Automated observations do not establish the complete requirement. ' . ($args['review'] ?? 'Independent assessment is required.');
            return CheckResult::of(CheckOutcome::ManualReview, $message, $evidence, 'REQUIREMENT_HUMAN_CONFIRMATION');
        }
        return CheckResult::of(CheckOutcome::Pass, 'All mapped technical evidence conditions passed in the assessed scope.', $evidence);
    }

    private static function combine(array $outcomes, bool $any): CheckOutcome
    {
        if ($outcomes === []) return CheckOutcome::Unknown;
        if ($any && in_array(CheckOutcome::Pass, $outcomes, true)) return CheckOutcome::Pass;
        if (!$any && in_array(CheckOutcome::Fail, $outcomes, true)) return CheckOutcome::Fail;
        if (in_array(CheckOutcome::Unknown, $outcomes, true)) return CheckOutcome::Unknown;
        if (in_array(CheckOutcome::ManualReview, $outcomes, true)) return CheckOutcome::ManualReview;
        return $any ? CheckOutcome::Fail : CheckOutcome::Pass;
    }
}
