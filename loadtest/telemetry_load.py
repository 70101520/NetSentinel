"""Dependency-free telemetry load probe; never stores or prints its token."""
import argparse,json,statistics,time,uuid
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
from urllib.request import Request,urlopen

def payload(size:int,endpoint:int)->bytes:
    now=datetime.now(timezone.utc).isoformat()
    events=[{"event_id":str(uuid.uuid4()),"event_time":now,"hostname":f"endpoint-{endpoint:04d}","domain":"load.example.com","protocol":"HTTPS","port":443,"action":"ALLOW","bytes_uploaded":128,"bytes_downloaded":512} for _ in range(size)]
    return json.dumps({"events":events},separators=(",",":")).encode()

def send(url:str,token:str,body:bytes)->tuple[float,int]:
    started=time.perf_counter()
    with urlopen(Request(url,data=body,headers={"Content-Type":"application/json","X-Service-Token":token}),timeout=15) as response:
        result=json.load(response)
    return (time.perf_counter()-started)*1000,result["accepted"]

def percentile(values:list[float],fraction:float)->float:
    return sorted(values)[min(len(values)-1,int((len(values)-1)*fraction))]

def main()->None:
    parser=argparse.ArgumentParser(); parser.add_argument("--url",required=True); parser.add_argument("--token",required=True); parser.add_argument("--events",type=int,required=True); parser.add_argument("--batch",type=int,default=100); parser.add_argument("--concurrency",type=int,default=8); parser.add_argument("--endpoints",type=int,default=500); args=parser.parse_args()
    bodies=[]; remaining=args.events; index=0
    while remaining:
        size=min(args.batch,remaining); bodies.append(payload(size,index%args.endpoints)); remaining-=size; index+=1
    started=time.perf_counter(); latencies=[]; accepted=0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures=[pool.submit(send,args.url,args.token,body) for body in bodies]
        for future in as_completed(futures):
            latency,count=future.result(); latencies.append(latency); accepted+=count
    elapsed=time.perf_counter()-started
    print(json.dumps({"events":accepted,"requests":len(bodies),"seconds":round(elapsed,3),"accepted_events_per_second":round(accepted/elapsed,1),"latency_ms":{"p50":round(statistics.median(latencies),2),"p95":round(percentile(latencies,.95),2),"p99":round(percentile(latencies,.99),2)}}))
if __name__=="__main__": main()
