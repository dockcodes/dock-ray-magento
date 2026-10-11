<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Config\Backend;

use Magento\Framework\App\Config\Value;

/** A pasted token often brings a trailing space or newline with it. */
class Trimmed extends Value
{
    public function beforeSave()
    {
        $this->setValue(trim(strip_tags((string) $this->getValue())));

        return parent::beforeSave();
    }
}
