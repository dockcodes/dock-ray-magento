<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Block\Adminhtml\System\Config;

use DockCodes\DockRay\Block\Adminhtml\Dashboard;
use Magento\Framework\Data\Form\Element\AbstractElement;
use Magento\Framework\Data\Form\Element\Renderer\RendererInterface;

/**
 * The branded header of Stores → Configuration → DockRay: logo, status of the
 * connection, the test button and a way to the overview page.
 */
class Header extends Dashboard implements RendererInterface
{
    protected $_template = 'DockCodes_DockRay::system/config/header.phtml';

    public function render(AbstractElement $element)
    {
        return $this->toHtml();
    }
}
