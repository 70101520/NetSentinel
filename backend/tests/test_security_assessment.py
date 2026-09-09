from types import SimpleNamespace

from app.security_assessment import evaluate_security

def device(status="ONLINE",metrics=None):
    return SimpleNamespace(current_status=status,metadata_={} if metrics is None else {"system_metrics":metrics})

def test_assessment_reports_health_and_exposed_services_without_exploitation():
    findings=evaluate_security(device("OFFLINE"),[23,445,3389])
    titles={item["title"] for item in findings}
    assert {"Agent is offline","System health metrics unavailable","Telnet service is reachable","SMB service is reachable","RDP service is reachable"}<=titles
    assert all("exploit" not in item["title"].lower() for item in findings)

def test_assessment_reports_high_resource_utilization():
    findings=evaluate_security(device(metrics={"cpu_percent":91,"memory_percent":92,"disk_percent":93}),[])
    assert {(item["category"],item["severity"]) for item in findings}>={("health","medium"),("health","high")}

def test_healthy_values_do_not_create_false_resource_findings():
    findings=evaluate_security(device(metrics={"cpu_percent":10,"memory_percent":20,"disk_percent":30}),[443])
    assert findings==[]
