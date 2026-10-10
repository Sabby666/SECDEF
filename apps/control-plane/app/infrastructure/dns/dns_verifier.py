import dns.resolver
import dns.exception
import structlog
from typing import Optional

logger = structlog.get_logger("asm.dns")

class DNSVerifier:
    def __init__(self, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    async def verify_txt_record(self, domain_name: str, expected_token: str) -> bool:
        """
        Checks if the expected_token is present in the TXT records of the domain.
        Returns True if verified, False otherwise.
        """
        try:
            # We look for the token at the root of the domain, or at a specific subdomain like _asm.
            # As per standard practice, we'll check `_asm.<domain>`
            target_domain = f"_asm.{domain_name}"
            
            # dns.resolver.resolve is blocking in dnspython by default, but we can use resolve() wrapped or async resolver
            # Since dnspython 2.0+, there is resolve() which is synchronous, and resolve() async equivalent using asyncio
            # Wait, dnspython's async usage:
            answers = await dns.asyncresolver.resolve(target_domain, "TXT", lifetime=self.resolver.lifetime)
            
            # Cap the number of records we parse to prevent resource exhaustion
            max_records = 50
            records_parsed = 0
            
            for rdata in answers:
                if records_parsed >= max_records:
                    logger.warning("dns_verification_max_records_reached", domain_name=domain_name)
                    break
                    
                for txt_string in rdata.strings:
                    # strings returns bytes
                    decoded = txt_string.decode('utf-8').strip()
                    # Enforce exact match semantics
                    if decoded == expected_token:
                        return True
                records_parsed += 1
                        
            return False
            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            logger.info("dns_verification_no_record", domain_name=domain_name)
            return False
        except dns.exception.Timeout:
            logger.warning("dns_verification_timeout", domain_name=domain_name)
            return False
        except Exception as e:
            logger.error("dns_verification_error", domain_name=domain_name, error=str(e))
            return False
