<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Engine/Context.php';
require_once __DIR__ . '/../src/Engine/Checks/AdminAclCheck.php';

use Magebean\Engine\Checks\AdminAclCheck;
use Magebean\Engine\Context;

function assertResult(mixed $expected, array $actual, string $label): void
{
    if (($actual[0] ?? null) !== $expected) {
        fwrite(STDERR, sprintf(
            "%s: expected %s, got %s (%s)\n",
            $label,
            var_export($expected, true),
            var_export($actual[0] ?? null, true),
            (string)($actual[1] ?? '')
        ));
        exit(1);
    }
}

$validRows = [
    'admin_user' => [
        ['user_id' => 7, 'username' => 'security.admin', 'is_active' => 1],
    ],
    'authorization_role' => [
        ['role_id' => 1, 'parent_id' => 0, 'role_type' => 'G', 'user_id' => 0, 'role_name' => 'Administrators'],
        ['role_id' => 2, 'parent_id' => 1, 'role_type' => 'U', 'user_id' => 7, 'role_name' => 'security.admin'],
    ],
    'authorization_rule' => [
        ['rule_id' => 1, 'role_id' => 1, 'resource_id' => 'Magento_Backend::admin', 'permission' => 'allow'],
    ],
];

$validContext = new Context(__DIR__, '', '', ['admin_acl_rows' => $validRows]);
assertResult(true, (new AdminAclCheck($validContext))->roleAssignmentsValid([]), 'valid assignments');

$invalidRows = $validRows;
$invalidRows['admin_user'][] = ['user_id' => 8, 'username' => 'unassigned.admin', 'is_active' => 1];
$invalidRows['authorization_role'][] = ['role_id' => 3, 'parent_id' => 999, 'role_type' => 'U', 'user_id' => 404, 'role_name' => 'orphan'];
$invalidRows['authorization_rule'][] = ['rule_id' => 2, 'role_id' => 999, 'resource_id' => 'Vendor_Module::config', 'permission' => 'allow'];
$invalidContext = new Context(__DIR__, '', '', ['admin_acl_rows' => $invalidRows]);
assertResult(false, (new AdminAclCheck($invalidContext))->roleAssignmentsValid([]), 'invalid assignments');

$globalRows = $validRows;
$globalRows['authorization_rule'][0]['resource_id'] = 'Magento_Backend::all';
$globalContext = new Context(__DIR__, '', '', ['admin_acl_rows' => $globalRows]);
$globalCheck = new AdminAclCheck($globalContext);
assertResult(false, $globalCheck->globalAclRestricted([]), 'unapproved global ACL');
assertResult(false, $globalCheck->globalAclRestricted([
    'approved_global_role_names' => ['Administrators'],
]), 'approved global role with unapproved user');
assertResult(true, $globalCheck->globalAclRestricted([
    'approved_global_role_names' => ['Administrators'],
    'approved_global_usernames' => ['security.admin'],
]), 'approved global role and user');
assertResult(true, (new AdminAclCheck($validContext))->globalAclRestricted([]), 'no global ACL');

$unknownContext = new Context(__DIR__ . '/fixture-without-env', '');
$unknownCheck = new AdminAclCheck($unknownContext);
assertResult(null, $unknownCheck->roleAssignmentsValid([]), 'missing database evidence for role assignments');
assertResult(null, $unknownCheck->globalAclRestricted([]), 'missing database evidence for global ACL');

echo "AdminAclCheckTest: PASS\n";