<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Console\Command;

use DockCodes\DockRay\Model\Inventory\State;
use DockCodes\DockRay\Model\Reporter;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `bin/magento dockray:test` - the admin button, for deployments without a browser. */
class TestCommand extends Command
{
    public function __construct(private readonly Reporter $reporter, private readonly State $state)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('dockray:test')
            ->setDescription('Sends a test event to DockRay and waits for the answer');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if (! $this->reporter->isConfigured()) {
            $output->writeln('<error>DockRay is not configured - set dockray/connection/token and dockray/connection/private_key.</error>');

            return Command::FAILURE;
        }

        $eventId = $this->reporter->sendTest();
        $this->state->saveTest($eventId !== null, $eventId);

        if ($eventId === null) {
            $output->writeln('<error>Could not send the test event. Check the token and the private key.</error>');

            return Command::FAILURE;
        }

        $output->writeln('<info>Sent. Event ID: '.$eventId.'</info>');

        return Command::SUCCESS;
    }
}
