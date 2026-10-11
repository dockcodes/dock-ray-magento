<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Setup;

use DockCodes\DockRay\Model\Config;
use DockCodes\DockRay\Model\Inventory\State;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;
use Magento\Framework\Setup\UninstallInterface;

/**
 * `bin/magento module:uninstall DockCodes_DockRay` removes everything the
 * module stored: its settings and the remembered report and test result.
 */
class Uninstall implements UninstallInterface
{
    public function uninstall(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $setup->startSetup();
        $connection = $setup->getConnection();

        $connection->delete($setup->getTable('core_config_data'), ['path IN (?)' => Config::PATHS]);
        $connection->delete($setup->getTable('flag'), ['flag_code IN (?)' => State::FLAGS]);

        $setup->endSetup();
    }
}
