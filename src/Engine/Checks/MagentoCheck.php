<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class MagentoCheck
{
    private Context $ctx;
    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }
    public function stub(array $args): array
    {
        return [true, 'MagentoCheck stub PASS'];
    }
}
