import pytest

from app.classifier import InvalidIOC, classify_ioc
from app.schemas import IOCType


@pytest.mark.parametrize(("raw","value","kind"),[
    (" 8.8.8.8 ","8.8.8.8",IOCType.IPV4),("2001:0db8::1","2001:db8::1",IOCType.IPV6),
    ("Example.COM.","example.com",IOCType.DOMAIN),("HTTPS://Example.COM/a#x","https://example.com/a",IOCType.URL),
    ("https://example.com:443/path","https://example.com/path",IOCType.URL),
    ("a"*32,"a"*32,IOCType.MD5),("B"*40,"b"*40,IOCType.SHA1),("c"*64,"c"*64,IOCType.SHA256),
    ("cve-2021-44228","CVE-2021-44228",IOCType.CVE),
])
def test_classification(raw,value,kind):
    result=classify_ioc(raw); assert (result.value,result.type)==(value,kind)

@pytest.mark.parametrize("raw",[
    "", "not an ioc", "ftp://example.com", "999.2.3.4", "example", "a"*31,
    "https:///missing", "https://user:pass@example.com", "https://example.com:99999",
])
def test_invalid(raw):
    with pytest.raises(InvalidIOC): classify_ioc(raw)
