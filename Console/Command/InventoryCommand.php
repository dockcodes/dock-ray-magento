<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Console\Command;

use DockCodes\DockRay\Model\Inventory\InventoryService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `bin/magento dockray:inventory:send` - the "Send now" button, from a deployment script. */
class InventoryCommand extends Command
{
    public function __construct(private readonly InventoryService $inventory)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('dockray:inventory:send')
            ->setDescription('Sends the software inventory to DockRay for vulnerability checks');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if (! $this->inventory->isEnabled()) {
            $output->writeln('<error>Vulnerability checks are off, or the token and the private key are missing.</error>');

            return Command::FAILURE;
        }

        $result = $this->inventory->run('manual');

        if ($result === null) {
            $output->writeln('<comment>A report is already being sent. Try again in a moment.</comment>');

            return Command::FAILURE;
        }

        if (! $result['success']) {
            $output->writeln(sprintf('<error>The report could not be sent (%s, HTTP %d).</error>', $result['error'], $result['status']));

            return Command::FAILURE;
        }

        $report = $result['report'];
        $output->writeln(sprintf(
            '<info>Report sent: %d components checked, %d vulnerable, %d to verify.</info>',
            $report['components'],
            $report['vulnerable'],
            $report['unverified'],
        ));

        foreach ($report['items'] as $item) {
            $output->writeln(sprintf(
                '  [%s] %s %s - %s%s',
                $item['severity'],
                $item['slug'],
                $item['version'],
                $item['title'],
                $item['fixed_in'] !== null ? ' (fixed in '.$item['fixed_in'].')' : '',
            ));
        }

        return Command::SUCCESS;
    }
}
