<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Console\Command;

use DockCodes\DockRay\Model\Security\SecurityService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `bin/magento dockray:security:send` - the "Send now" button, from a
 * deployment script: scans right away and sends the security report.
 */
class SecurityCommand extends Command
{
    public function __construct(private readonly SecurityService $security)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('dockray:security:send')
            ->setDescription('Scans the store and sends the security report to DockRay');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if (! $this->security->isEnabled()) {
            $output->writeln('<error>The security report is off, or the token and the private key are missing.</error>');

            return Command::FAILURE;
        }

        $result = $this->security->run('manual');

        if ($result === null) {
            $output->writeln('<comment>A report is already being sent. Try again in a moment.</comment>');

            return Command::FAILURE;
        }

        $scan = is_array($result['scan'] ?? null) ? $result['scan'] : null;

        if ($scan !== null) {
            $output->writeln(sprintf(
                '%d files checked in %.1f s%s.',
                (int) $scan['files'],
                ((int) $scan['duration_ms']) / 1000,
                ! empty($scan['truncated']) ? ' - the scan stopped at its limit and continues within the hour' : '',
            ));
        }

        if (! $result['success']) {
            $output->writeln(sprintf('<error>The report could not be sent (%s, HTTP %d).</error>', $result['error'], $result['status']));

            if (($result['message'] ?? '') !== '') {
                $output->writeln('Server message: '.OutputFormatter::escape((string) $result['message']));
            }

            return Command::FAILURE;
        }

        $report = $result['report'];
        $counts = [];

        foreach ($report['findings'] as $severity => $count) {
            $counts[] = $severity.' '.(int) $count;
        }

        $output->writeln('<info>Report sent. Open findings: '.OutputFormatter::escape(implode(', ', $counts)).'</info>');

        // Everything below came from the server: stripped of control characters
        // when stored, escaped here so a `<tag>` cannot style or hide output.
        foreach ($report['items'] as $item) {
            $output->writeln(OutputFormatter::escape(sprintf(
                '  [%s] %s%s',
                $item['severity'],
                $item['title'] !== '' ? $item['title'] : (string) $item['code'],
                $item['subject'] !== '' ? ': '.$item['subject'] : '',
            )));
        }

        foreach ($report['items'] as $item) {
            if ($item['url'] !== null) {
                $output->writeln('Details: '.OutputFormatter::escape($item['url']));

                break;
            }
        }

        return Command::SUCCESS;
    }
}
