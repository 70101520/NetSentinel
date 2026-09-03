"""Enrollment/heartbeat simulator; this is not the production endpoint agent."""
import argparse,json,time,uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
from urllib.request import Request,urlopen
def post(url,body,headers=None):
    started=time.perf_counter()
    with urlopen(Request(url,data=json.dumps(body).encode(),headers={"Content-Type":"application/json",**(headers or {})}),timeout=15) as response:return json.load(response),(time.perf_counter()-started)*1000
def main():
    p=argparse.ArgumentParser();p.add_argument("--url",required=True);p.add_argument("--enrollment-token",required=True);p.add_argument("--devices",type=int,default=500);p.add_argument("--concurrency",type=int,default=16);a=p.parse_args()
    def enroll(i):return post(a.url+"/api/v1/agents/enroll",{"enrollment_token":a.enrollment_token,"installation_id":f"sim-{uuid.uuid4()}","hostname":f"SIM-{i:04d}","os_name":"Windows","os_version":"11","architecture":"x64","initial_ip":f"10.20.{i//254}.{i%254+1}","agent_version":"simulator-0.1"})[0]
    with ThreadPoolExecutor(a.concurrency) as x: identities=list(x.map(enroll,range(a.devices)))
    def beat(pair):
        i,item=pair; body={"device_id":item["device_id"],"timestamp":datetime.now(timezone.utc).isoformat(),"hostname":f"SIM-{i:04d}","agent_version":"simulator-0.1","os_name":"Windows","active_ips":[f"10.20.{i//254}.{i%254+1}"],"uptime_seconds":3600};return post(a.url+"/api/v1/agents/heartbeat",body,{"X-Agent-Credential":item["credential"]})[1]
    started=time.perf_counter()
    with ThreadPoolExecutor(a.concurrency) as x: latency=list(x.map(beat,enumerate(identities)))
    latency.sort(); print(json.dumps({"devices":a.devices,"seconds":round(time.perf_counter()-started,3),"p50_ms":latency[len(latency)//2],"p95_ms":latency[int(len(latency)*.95)],"p99_ms":latency[int(len(latency)*.99)]}))
if __name__=="__main__":main()
