<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Checks\MagentoCheck;
use Magebean\Engine\Context;
$n = 0;
function adminConfigAssert(bool $ok, string $message): void { global $n; ++$n; if (!$ok) throw new RuntimeException($message); }
$root = sys_get_temp_dir().'/mb-admin-config-'.bin2hex(random_bytes(6));
mkdir($root.'/app/etc', 0777, true);
$write = static function (array $config) use ($root): MagentoCheck {
    file_put_contents($root.'/app/etc/config.php', '<?php return '.var_export($config, true).';');
    return new MagentoCheck(new Context($root, ''));
};
try {
    $check = $write(['modules'=>['Magento_TwoFactorAuth'=>1], 'system'=>['default'=>['twofactorauth'=>['general'=>['force_providers'=>'google']]]]]);
    $result = $check->adminTwoFactorAuthEnabled([]);
    adminConfigAssert($result[0] === true && $result[2]['providers'] === ['google'], 'Native Google engine works without fictional provider module');
    adminConfigAssert($result[2]['enrollment_verified'] === false, 'Provider configuration never proves enrollment');
    foreach ([['Magento_TwoFactorAuth'=>0], ['Magento_TwoFactorAuth'=>1,'Magento_AdminAdobeIms'=>1], ['Magento_TwoFactorAuth'=>'bad'], []] as $i=>$modules) {
        $check = $write(['modules'=>$modules]);
        adminConfigAssert($check->adminTwoFactorAuthEnabled([])[0] === ($i===0 ? false : null), 'Disabled, IMS, malformed and missing module states remain distinct');
    }
    foreach ([''=>null, 'unrecognized'=>null, 'google,duo_security'=>true] as $providers=>$expected) {
        $check = $write(['modules'=>['Magento_TwoFactorAuth'=>1], 'system'=>['default'=>['twofactorauth/general/force_providers'=>$providers]]]);
        adminConfigAssert($check->adminTwoFactorAuthEnabled([])[0] === $expected, 'Exact provider configuration result');
    }
    $check = $write(['modules'=>['Magento_TwoFactorAuth'=>1,'Magento_GoogleAuthenticator'=>1]]);
    adminConfigAssert($check->adminTwoFactorAuthEnabled([])[0] === null, 'Fictional provider module cannot substitute for configuration');
    foreach (['admin/security/use_form_key'=>1, 'admin/security/use_case_sensitive_login'=>1, 'admin/security/admin_account_sharing'=>0] as $path=>$safe) {
        foreach ([$safe=>true, 1-$safe=>false, 'invalid'=>null] as $value=>$expected) {
            $check = $write(['system'=>['default'=>[$path=>$value]]]);
            adminConfigAssert($check->adminSecurityFlagConfigured(['path'=>$path])[0] === $expected, 'Safe unsafe malformed Admin flag');
        }
        $check = $write([]);
        adminConfigAssert($check->adminSecurityFlagConfigured(['path'=>$path])[0] === null, 'Missing Admin flag unknown');
    }
    foreach ([[1,5,1,true],[0,5,1,false],[1,0,1,false],[1,6,1,false],[1,5,0,false],[9,5,1,null]] as [$type,$maximum,$interval,$expected]) {
        $check = $write(['system'=>['default'=>['admin/security/password_reset_protection_type'=>$type, 'admin/security/max_number_password_reset_requests'=>$maximum, 'admin/security/min_time_between_password_reset_requests'=>$interval]]]);
        adminConfigAssert($check->adminPasswordResetProtectionConfigured([])[0] === $expected, 'Independent reset protection and throttling policies');
    }
    $check=$write([]);
    adminConfigAssert($check->adminPasswordResetProtectionConfigured([])[0] === null, 'Missing reset policy unknown');
    foreach (['admin'=>false,'backend'=>false,'custom_route'=>true] as $route=>$expected) {
        file_put_contents($root.'/app/etc/env.php', '<?php return '.var_export(['backend'=>['frontName'=>$route]],true).';');
        adminConfigAssert($check->adminFrontNameDeclared([])[0] === $expected, 'Common Admin route rejected');
    }
    echo "BasicAdminConfigurationTest: $n assertions passed\n";
} finally {
    foreach (glob($root.'/app/etc/*') as $file) unlink($file);
    rmdir($root.'/app/etc');rmdir($root.'/app');rmdir($root);
}
