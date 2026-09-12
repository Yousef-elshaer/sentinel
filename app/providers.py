import asyncio
import base64
from abc import ABC, abstractmethod
from typing import ClassVar

import httpx

from app.classifier import ClassifiedIOC
from app.config import Settings
from app.schemas import IOCType, ProviderResult, ProviderStatus


class Provider(ABC):
    name: str
    supported_types: ClassVar[set[IOCType]]
    def __init__(self, client: httpx.AsyncClient, settings: Settings): self.client, self.settings = client, settings
    @abstractmethod
    async def lookup(self, ioc: ClassifiedIOC) -> ProviderResult: ...

    async def safe_lookup(self, ioc: ClassifiedIOC) -> ProviderResult:
        try:
            return await self.lookup(ioc)
        except httpx.TimeoutException:
            return ProviderResult(provider=self.name, status=ProviderStatus.TIMEOUT, error="Provider timed out")
        except httpx.HTTPStatusError as exc:
            status = ProviderStatus.AUTH_ERROR if exc.response.status_code in {401, 403} else ProviderStatus.RATE_LIMITED if exc.response.status_code == 429 else ProviderStatus.UNAVAILABLE
            return ProviderResult(provider=self.name, status=status, error=f"Provider returned HTTP {exc.response.status_code}")
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            return ProviderResult(provider=self.name, status=ProviderStatus.INVALID_RESPONSE, error="Provider response could not be processed")


class VirusTotal(Provider):
    name = "VirusTotal"
    supported_types: ClassVar[set[IOCType]] = {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.SHA1, IOCType.SHA256}
    async def lookup(self, ioc: ClassifiedIOC) -> ProviderResult:
        if not self.settings.virustotal_api_key:
            return ProviderResult(provider=self.name, status=ProviderStatus.SKIPPED, error="API key not configured")
        paths = {IOCType.IPV4:"ip_addresses", IOCType.IPV6:"ip_addresses", IOCType.DOMAIN:"domains", IOCType.MD5:"files", IOCType.SHA1:"files", IOCType.SHA256:"files"}
        if ioc.type == IOCType.URL:
            identifier = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("="); path = "urls"
        else: identifier, path = ioc.value, paths[ioc.type]
        response = await self.client.get(f"{self.settings.virustotal_base_url}/{path}/{identifier}", headers={"x-apikey":self.settings.virustotal_api_key})
        response.raise_for_status(); attrs = response.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {}); malicious = int(stats.get("malicious",0))
        return ProviderResult(provider=self.name,status=ProviderStatus.SUCCESS,malicious=malicious>0,
            confidence=min(100, malicious*10),malicious_detections=malicious,total_detections=sum(int(v) for v in stats.values()),
            categories=list((attrs.get("categories") or {}).values()),evidence={"reputation":attrs.get("reputation")})


class AbuseIPDB(Provider):
    name="AbuseIPDB"; supported_types: ClassVar[set[IOCType]]={IOCType.IPV4,IOCType.IPV6}
    async def lookup(self,ioc:ClassifiedIOC)->ProviderResult:
        if not self.settings.abuseipdb_api_key:
            return ProviderResult(provider=self.name,status=ProviderStatus.SKIPPED,error="API key not configured")
        response=await self.client.get(f"{self.settings.abuseipdb_base_url}/check",params={"ipAddress":ioc.value,"maxAgeInDays":90},headers={"Key":self.settings.abuseipdb_api_key,"Accept":"application/json"})
        response.raise_for_status(); data=response.json()["data"]; confidence=int(data.get("abuseConfidenceScore",0))
        return ProviderResult(provider=self.name,status=ProviderStatus.SUCCESS,malicious=confidence>=25,confidence=confidence,
            malicious_detections=int(data.get("totalReports",0)),categories=["reported_abuse"] if confidence else [],evidence={"country":data.get("countryCode"),"usage_type":data.get("usageType")})


class URLhaus(Provider):
    name="URLhaus"; supported_types: ClassVar[set[IOCType]]={IOCType.URL,IOCType.DOMAIN,IOCType.MD5,IOCType.SHA256}
    async def lookup(self,ioc:ClassifiedIOC)->ProviderResult:
        if not self.settings.urlhaus_auth_key:
            return ProviderResult(provider=self.name,status=ProviderStatus.SKIPPED,error="Auth-Key not configured")
        if ioc.type==IOCType.URL: endpoint,payload="url",{"url":ioc.value}
        elif ioc.type==IOCType.DOMAIN: endpoint,payload="host",{"host":ioc.value}
        else: endpoint,payload="payload",{"hash":ioc.value}
        response=await self.client.post(f"{self.settings.urlhaus_base_url}/{endpoint}/",data=payload,
                                        headers={"Auth-Key":self.settings.urlhaus_auth_key})
        response.raise_for_status(); data=response.json()
        found=data.get("query_status") not in {"no_results","invalid_url","invalid_host","hash_not_found"}
        return ProviderResult(provider=self.name,status=ProviderStatus.SUCCESS,malicious=found,confidence=85 if found else 0,
            malicious_detections=1 if found else 0,categories=[str(data.get("threat","malware_distribution"))] if found else [],evidence={"query_status":data.get("query_status")})


class CISAKEV(Provider):
    name="CISA KEV"; supported_types: ClassVar[set[IOCType]]={IOCType.CVE}
    async def lookup(self,ioc:ClassifiedIOC)->ProviderResult:
        response=await self.client.get(self.settings.cisa_kev_url); response.raise_for_status(); data=response.json()
        match=next((v for v in data["vulnerabilities"] if v.get("cveID","" ).upper()==ioc.value),None)
        return ProviderResult(provider=self.name,status=ProviderStatus.SUCCESS,malicious=bool(match),confidence=100 if match else 0,
            malicious_detections=1 if match else 0,categories=["known_exploited"] if match else [],evidence=match or {})


async def query_providers(ioc: ClassifiedIOC, client: httpx.AsyncClient, settings: Settings) -> list[ProviderResult]:
    providers=[VirusTotal(client,settings),AbuseIPDB(client,settings),URLhaus(client,settings),CISAKEV(client,settings)]
    applicable=[provider for provider in providers if ioc.type in provider.supported_types]
    return list(await asyncio.gather(*(provider.safe_lookup(ioc) for provider in applicable)))
