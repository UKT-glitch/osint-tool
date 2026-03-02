"""osint_tool.modules package – public registry of all modules."""

from osint_tool.modules.base import BaseModule
from osint_tool.modules.email_osint import EmailModule
from osint_tool.modules.ip_domain import IpDomainModule
from osint_tool.modules.phone import PhoneModule
from osint_tool.modules.username import UsernameModule

__all__ = [
    "BaseModule",
    "UsernameModule",
    "EmailModule",
    "IpDomainModule",
    "PhoneModule",
]

# Registry mapping module name → class
MODULE_REGISTRY: dict[str, type[BaseModule]] = {
    UsernameModule.name: UsernameModule,
    EmailModule.name: EmailModule,
    IpDomainModule.name: IpDomainModule,
    PhoneModule.name: PhoneModule,
}
