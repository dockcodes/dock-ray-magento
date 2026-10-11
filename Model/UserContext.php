<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model;

use Magento\Authorization\Model\UserContextInterface;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\User\Model\UserFactory;

/**
 * Who was logged in when the error happened - the customer on the storefront
 * and in REST/GraphQL, the admin user in the back office.
 *
 * Only called while an error is being reported and only with "send user
 * identity" on, so a measured request never loads a customer.
 */
class UserContext
{
    public function __construct(
        private readonly UserContextInterface $userContext,
        private readonly CustomerRepositoryInterface $customerRepository,
        private readonly UserFactory $adminUserFactory,
    ) {
    }

    /** @return array{id: int, username?: string, email?: string}|null */
    public function resolve(): ?array
    {
        try {
            $id = (int) $this->userContext->getUserId();
            $type = (int) $this->userContext->getUserType();
        } catch (\Throwable) {
            return null;
        }

        if ($id <= 0) {
            return null;
        }

        try {
            if ($type === UserContextInterface::USER_TYPE_CUSTOMER) {
                $customer = $this->customerRepository->getById($id);

                return array_filter([
                    'id' => $id,
                    'username' => trim($customer->getFirstname().' '.$customer->getLastname()),
                    'email' => (string) $customer->getEmail(),
                ], static fn ($value): bool => $value !== '' && $value !== null);
            }

            if ($type === UserContextInterface::USER_TYPE_ADMIN) {
                $user = $this->adminUserFactory->create()->load($id);

                return array_filter([
                    'id' => $id,
                    'username' => (string) $user->getUserName(),
                    'email' => (string) $user->getEmail(),
                ], static fn ($value): bool => $value !== '' && $value !== null);
            }
        } catch (\Throwable) {
            // The id alone is still worth reporting.
        }

        return ['id' => $id];
    }
}
