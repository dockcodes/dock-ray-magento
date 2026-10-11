<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Config\Backend;

use Magento\Framework\App\Config\Value;

/**
 * The browser validates the range, but a request can skip the browser. Anything
 * outside 0…1 is clamped rather than refused: a rate of 5 means "everything".
 */
class SampleRate extends Value
{
    public function beforeSave()
    {
        $value = str_replace(',', '.', trim((string) $this->getValue()));
        $rate = is_numeric($value) ? max(0.0, min(1.0, (float) $value)) : 0.0;

        $this->setValue(rtrim(rtrim(number_format($rate, 4, '.', ''), '0'), '.') ?: '0');

        return parent::beforeSave();
    }
}
