<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Setup;

use DockCodes\DockRay\Model\Config;
use DockCodes\DockRay\Model\Inventory\State;
use DockCodes\DockRay\Model\Security\SecurityService;
use DockCodes\DockRay\Model\Security\State as SecurityState;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;
use Magento\Framework\Setup\UninstallInterface;

/**
 * `bin/magento module:uninstall DockCodes_DockRay` removes everything the
 * module stored: its settings, the remembered reports and test result, and
 * the security report's hash cache in `var/dockray/`.
 */
class Uninstall implements UninstallInterface
{
    public function __construct(private readonly DirectoryList $directoryList)
    {
    }

    public function uninstall(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $setup->startSetup();
        $connection = $setup->getConnection();

        $connection->delete($setup->getTable('core_config_data'), ['path IN (?)' => Config::PATHS]);
        $connection->delete($setup->getTable('flag'), ['flag_code IN (?)' => array_merge(State::FLAGS, SecurityState::FLAGS)]);

        try {
            $file = rtrim($this->directoryList->getPath(DirectoryList::VAR_DIR), '/\\').'/'.SecurityService::CACHE_FILE;

            if (is_file($file) && ! is_link($file)) {
                @unlink($file);
            }

            @rmdir(dirname($file));
        } catch (\Throwable) {
            // A missing var directory leaves nothing to remove.
        }

        $setup->endSetup();
    }
}
