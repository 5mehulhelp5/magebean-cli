<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;
use PDO;
use PDOException;
use Throwable;

final class AdminAclCheck
{
    private Context $ctx;

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    public function roleAssignmentsValid(array $args): array
    {
        $envFile = (string)($args['env_file'] ?? 'app/etc/env.php');
        $injectedRows = $this->ctx->get('admin_acl_rows');
        if (is_array($injectedRows)) {
            $users = is_array($injectedRows['admin_user'] ?? null) ? $injectedRows['admin_user'] : [];
            $roles = is_array($injectedRows['authorization_role'] ?? null) ? $injectedRows['authorization_role'] : [];
            $rules = is_array($injectedRows['authorization_rule'] ?? null) ? $injectedRows['authorization_rule'] : [];
            $connectionEvidence = ['source' => 'context_rows'];
        } else {
            [$pdo, $prefix, $connectionEvidence, $error] = $this->connection($envFile);
            if (!$pdo instanceof PDO) {
                return [null, '[UNKNOWN] ' . $error, $connectionEvidence];
            }

            try {
                $users = $this->fetchAll($pdo, $prefix . 'admin_user', [
                    'user_id', 'username', 'is_active',
                ]);
                $roles = $this->fetchAll($pdo, $prefix . 'authorization_role', [
                    'role_id', 'parent_id', 'role_type', 'user_id', 'role_name',
                ]);
                $rules = $this->fetchAll($pdo, $prefix . 'authorization_rule', [
                    'rule_id', 'role_id', 'resource_id', 'permission',
                ]);
            } catch (Throwable $e) {
                return [null, '[UNKNOWN] Unable to read Magento Admin ACL tables: ' . $e->getMessage(), $connectionEvidence + [
                    'reason' => 'acl_query_failed',
                ]];
            }
        }

        $usersById = [];
        foreach ($users as $user) {
            $usersById[(int)$user['user_id']] = $user;
        }

        $rolesById = [];
        foreach ($roles as $role) {
            $rolesById[(int)$role['role_id']] = $role;
        }

        $rulesByRole = [];
        foreach ($rules as $rule) {
            $roleId = (int)$rule['role_id'];
            $rulesByRole[$roleId][] = $rule;
        }

        $findings = [];
        $activeUsers = 0;
        $assignedGroupIds = [];
        $userRolesByUser = [];

        foreach ($roles as $role) {
            $roleId = (int)$role['role_id'];
            $roleType = strtoupper(trim((string)$role['role_type']));
            $parentId = (int)$role['parent_id'];
            $userId = (int)$role['user_id'];

            if ($roleType === 'U') {
                $userRolesByUser[$userId][] = $role;
                if ($userId <= 0 || !isset($usersById[$userId])) {
                    $findings[] = $this->finding('orphan_user_role', [
                        'role_id' => $roleId,
                        'user_id' => $userId,
                    ]);
                }
                if ($parentId <= 0 || !isset($rolesById[$parentId])) {
                    $findings[] = $this->finding('missing_parent_role', [
                        'role_id' => $roleId,
                        'user_id' => $userId,
                        'parent_id' => $parentId,
                    ]);
                } elseif (strtoupper(trim((string)$rolesById[$parentId]['role_type'])) !== 'G') {
                    $findings[] = $this->finding('invalid_parent_role_type', [
                        'role_id' => $roleId,
                        'user_id' => $userId,
                        'parent_id' => $parentId,
                    ]);
                } else {
                    $assignedGroupIds[$parentId] = true;
                }
                continue;
            }

            if ($roleType === 'G') {
                if ($parentId > 0 && !isset($rolesById[$parentId])) {
                    $findings[] = $this->finding('orphan_group_role', [
                        'role_id' => $roleId,
                        'parent_id' => $parentId,
                        'role_name' => (string)$role['role_name'],
                    ]);
                }
                continue;
            }

            $findings[] = $this->finding('invalid_role_type', [
                'role_id' => $roleId,
                'role_type' => (string)$role['role_type'],
            ]);
        }

        foreach ($users as $user) {
            if ((int)$user['is_active'] !== 1) {
                continue;
            }
            $activeUsers++;
            $userId = (int)$user['user_id'];
            $assignedRoles = $userRolesByUser[$userId] ?? [];
            if ($assignedRoles === []) {
                $findings[] = $this->finding('active_user_without_role', [
                    'user_id' => $userId,
                    'username' => (string)$user['username'],
                ]);
            } elseif (count($assignedRoles) > 1) {
                $findings[] = $this->finding('user_with_multiple_role_assignments', [
                    'user_id' => $userId,
                    'username' => (string)$user['username'],
                    'role_ids' => array_values(array_map(
                        static fn(array $role): int => (int)$role['role_id'],
                        $assignedRoles
                    )),
                ]);
            }
        }

        foreach (array_keys($assignedGroupIds) as $groupRoleId) {
            if (($rulesByRole[$groupRoleId] ?? []) === []) {
                $role = $rolesById[$groupRoleId];
                $findings[] = $this->finding('assigned_role_without_acl_rules', [
                    'role_id' => $groupRoleId,
                    'role_name' => (string)$role['role_name'],
                ]);
            }
        }

        foreach ($rules as $rule) {
            $roleId = (int)$rule['role_id'];
            if ($roleId <= 0 || !isset($rolesById[$roleId])) {
                $findings[] = $this->finding('orphan_acl_rule', [
                    'rule_id' => (int)$rule['rule_id'],
                    'role_id' => $roleId,
                    'resource_id' => (string)$rule['resource_id'],
                ]);
            }
        }

        $evidence = $connectionEvidence + [
            'active_admin_users' => $activeUsers,
            'admin_users_seen' => count($users),
            'authorization_roles_seen' => count($roles),
            'authorization_rules_seen' => count($rules),
            'findings' => $findings,
        ];

        if ($findings !== []) {
            $lines = ['Invalid Magento Admin user/role ACL assignments:'];
            foreach ($findings as $finding) {
                $lines[] = '    - ' . $finding['type'] . ': ' . json_encode(
                    array_diff_key($finding, ['type' => true]),
                    JSON_UNESCAPED_SLASHES
                );
            }
            return [false, implode("\n", $lines), $evidence];
        }

        return [true, 'Active Magento Admin users have valid role and ACL assignments', $evidence];
    }

    public function globalAclRestricted(array $args): array
    {
        $envFile = (string)($args['env_file'] ?? 'app/etc/env.php');
        $injectedRows = $this->ctx->get('admin_acl_rows');
        if (is_array($injectedRows)) {
            $users = is_array($injectedRows['admin_user'] ?? null) ? $injectedRows['admin_user'] : [];
            $roles = is_array($injectedRows['authorization_role'] ?? null) ? $injectedRows['authorization_role'] : [];
            $rules = is_array($injectedRows['authorization_rule'] ?? null) ? $injectedRows['authorization_rule'] : [];
            $connectionEvidence = ['source' => 'context_rows'];
        } else {
            [$pdo, $prefix, $connectionEvidence, $error] = $this->connection($envFile);
            if (!$pdo instanceof PDO) {
                return [null, '[UNKNOWN] ' . $error, $connectionEvidence];
            }

            try {
                $users = $this->fetchAll($pdo, $prefix . 'admin_user', [
                    'user_id', 'username', 'is_active',
                ]);
                $roles = $this->fetchAll($pdo, $prefix . 'authorization_role', [
                    'role_id', 'parent_id', 'role_type', 'user_id', 'role_name',
                ]);
                $rules = $this->fetchAll($pdo, $prefix . 'authorization_rule', [
                    'rule_id', 'role_id', 'resource_id', 'permission',
                ]);
            } catch (Throwable $e) {
                return [null, '[UNKNOWN] Unable to read Magento Admin ACL tables: ' . $e->getMessage(), $connectionEvidence + [
                    'reason' => 'acl_query_failed',
                ]];
            }
        }

        $globalResources = $this->normalizedStrings($args['global_resources'] ?? [
            'Magento_Backend::all',
            'Magento_Adminhtml::all',
        ]);
        $approvedRoleIds = $this->normalizedIds($args['approved_global_role_ids'] ?? []);
        $approvedRoleNames = $this->normalizedStrings($args['approved_global_role_names'] ?? []);
        $approvedUserIds = $this->normalizedIds($args['approved_global_user_ids'] ?? []);
        $approvedUsernames = $this->normalizedStrings($args['approved_global_usernames'] ?? []);

        $usersById = [];
        foreach ($users as $user) {
            $usersById[(int)$user['user_id']] = $user;
        }

        $rolesById = [];
        $usersByGroupRole = [];
        foreach ($roles as $role) {
            $roleId = (int)$role['role_id'];
            $rolesById[$roleId] = $role;
            if (strtoupper(trim((string)$role['role_type'])) === 'U') {
                $usersByGroupRole[(int)$role['parent_id']][] = (int)$role['user_id'];
            }
        }

        $globalRoleIds = [];
        foreach ($rules as $rule) {
            $permission = strtolower(trim((string)$rule['permission']));
            $resource = strtolower(trim((string)$rule['resource_id']));
            if ($permission === 'allow' && in_array($resource, $globalResources, true)) {
                $globalRoleIds[(int)$rule['role_id']] = true;
            }
        }

        $findings = [];
        $globalRoles = [];
        foreach (array_keys($globalRoleIds) as $roleId) {
            $role = $rolesById[$roleId] ?? null;
            $roleName = is_array($role) ? trim((string)$role['role_name']) : '';
            $roleApproved = in_array($roleId, $approvedRoleIds, true)
                || ($roleName !== '' && in_array(strtolower($roleName), $approvedRoleNames, true));

            $inheritingUsers = [];
            foreach (array_values(array_unique($usersByGroupRole[$roleId] ?? [])) as $userId) {
                $user = $usersById[$userId] ?? null;
                if (!is_array($user)) {
                    continue;
                }
                $username = trim((string)$user['username']);
                $active = (int)$user['is_active'] === 1;
                $userApproved = in_array($userId, $approvedUserIds, true)
                    || ($username !== '' && in_array(strtolower($username), $approvedUsernames, true));
                $inheritingUsers[] = [
                    'user_id' => $userId,
                    'username' => $username,
                    'active' => $active,
                    'approved' => $userApproved,
                ];
                if ($active && !$userApproved) {
                    $findings[] = $this->finding('unapproved_global_acl_user', [
                        'role_id' => $roleId,
                        'role_name' => $roleName,
                        'user_id' => $userId,
                        'username' => $username,
                    ]);
                }
            }

            $globalRoles[] = [
                'role_id' => $roleId,
                'role_name' => $roleName,
                'approved' => $roleApproved,
                'users' => $inheritingUsers,
            ];
            if (!$roleApproved) {
                $findings[] = $this->finding('unapproved_global_acl_role', [
                    'role_id' => $roleId,
                    'role_name' => $roleName,
                ]);
            }
        }

        $evidence = $connectionEvidence + [
            'global_resources' => $globalResources,
            'approved_exception_policy' => [
                'role_ids' => $approvedRoleIds,
                'role_names' => $approvedRoleNames,
                'user_ids' => $approvedUserIds,
                'usernames' => $approvedUsernames,
            ],
            'global_roles' => $globalRoles,
            'findings' => $findings,
        ];

        if ($findings !== []) {
            $lines = ['Unapproved Magento global Admin ACL assignments:'];
            foreach ($findings as $finding) {
                $lines[] = '    - ' . $finding['type'] . ': ' . json_encode(
                    array_diff_key($finding, ['type' => true]),
                    JSON_UNESCAPED_SLASHES
                );
            }
            return [false, implode("\n", $lines), $evidence];
        }

        if ($globalRoles === []) {
            return [true, 'No Magento Admin roles have global ACL access', $evidence];
        }

        return [true, 'Global Magento Admin ACL access is limited to approved roles and users', $evidence];
    }

    /** @return list<string> */
    private function normalizedStrings(mixed $values): array
    {
        if (!is_array($values)) {
            return [];
        }
        return array_values(array_unique(array_filter(array_map(
            static fn(mixed $value): string => strtolower(trim((string)$value)),
            $values
        ), static fn(string $value): bool => $value !== '')));
    }

    /** @return list<int> */
    private function normalizedIds(mixed $values): array
    {
        if (!is_array($values)) {
            return [];
        }
        return array_values(array_unique(array_filter(array_map(
            static fn(mixed $value): int => (int)$value,
            $values
        ), static fn(int $value): bool => $value > 0)));
    }
    private function connection(string $envFile): array
    {
        $injected = $this->ctx->get('pdo');
        if ($injected instanceof PDO) {
            $prefix = (string)$this->ctx->get('db_table_prefix', '');
            if (!$this->validPrefix($prefix)) {
                return [null, '', ['source' => 'context'], 'Invalid database table prefix'];
            }
            return [$injected, $prefix, ['source' => 'context', 'table_prefix' => $prefix], ''];
        }

        $path = $this->ctx->abs($envFile);
        if (!is_file($path) || !is_readable($path)) {
            return [null, '', ['source' => $envFile, 'reason' => 'env_file_unavailable'], "Magento database configuration is unavailable: {$envFile}"];
        }

        try {
            $env = include $path;
        } catch (Throwable $e) {
            return [null, '', ['source' => $envFile, 'reason' => 'env_file_load_failed'], 'Unable to load Magento database configuration'];
        }
        if (!is_array($env)) {
            return [null, '', ['source' => $envFile, 'reason' => 'invalid_env_file'], 'Magento env.php did not return a configuration array'];
        }

        $db = $env['db']['connection']['default'] ?? null;
        if (!is_array($db)) {
            return [null, '', ['source' => $envFile, 'reason' => 'db_config_missing'], 'Magento default database connection is missing'];
        }

        $prefix = (string)($env['db']['table_prefix'] ?? '');
        if (!$this->validPrefix($prefix)) {
            return [null, '', ['source' => $envFile, 'reason' => 'invalid_table_prefix'], 'Invalid database table prefix'];
        }

        $host = trim((string)($db['host'] ?? 'localhost'));
        $dbname = trim((string)($db['dbname'] ?? ''));
        $username = (string)($db['username'] ?? '');
        $password = (string)($db['password'] ?? '');
        $port = isset($db['port']) ? trim((string)$db['port']) : '';
        if ($port === '' && substr_count($host, ':') === 1) {
            [$host, $port] = explode(':', $host, 2);
        }
        if ($dbname === '' || $username === '') {
            return [null, '', ['source' => $envFile, 'reason' => 'incomplete_db_config'], 'Magento database configuration is incomplete'];
        }

        $dsn = 'mysql:host=' . $host . ';dbname=' . $dbname . ';charset=utf8mb4';
        if ($port !== '') {
            $dsn .= ';port=' . $port;
        }

        try {
            $pdo = new PDO($dsn, $username, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
        } catch (PDOException $e) {
            return [null, '', [
                'source' => $envFile,
                'reason' => 'db_connection_failed',
                'database' => $dbname,
                'host' => $host,
            ], 'Unable to connect to the Magento database'];
        }

        return [$pdo, $prefix, [
            'source' => $envFile,
            'database' => $dbname,
            'host' => $host,
            'table_prefix' => $prefix,
        ], ''];
    }

    private function fetchAll(PDO $pdo, string $table, array $columns): array
    {
        if (!$this->validIdentifier($table)) {
            throw new \RuntimeException('Invalid database table name');
        }
        foreach ($columns as $column) {
            if (!$this->validIdentifier($column)) {
                throw new \RuntimeException('Invalid database column name');
            }
        }
        $quotedColumns = implode(', ', array_map(
            static fn(string $column): string => '`' . $column . '`',
            $columns
        ));
        $statement = $pdo->query('SELECT ' . $quotedColumns . ' FROM `' . $table . '`');
        if ($statement === false) {
            throw new \RuntimeException('Query failed for ' . $table);
        }
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        return is_array($rows) ? $rows : [];
    }

    private function validPrefix(string $prefix): bool
    {
        return $prefix === '' || preg_match('/^[A-Za-z0-9_]+$/', $prefix) === 1;
    }

    private function validIdentifier(string $identifier): bool
    {
        return preg_match('/^[A-Za-z0-9_]+$/', $identifier) === 1;
    }

    private function finding(string $type, array $details): array
    {
        return ['type' => $type] + $details;
    }
}