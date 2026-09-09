import React from 'react';
import {api,ApiFailure,AuthenticationRequired} from './api';
import './graphs.css';

type GraphTarget={source_type:'agent'|'snmp';id:string;name:string};
type GraphInterface={index?:number;name:string;port_name?:string;status:string;speed_bps?:number;receive_bps?:number;send_bps?:number};
type GraphSample={sampled_at:string;uptime_seconds?:number;cpu_percent?:number;memory_percent?:number;disk_percent?:number;network_receive_bps?:number;network_send_bps?:number;interfaces:GraphInterface[]};
type GraphData={identity:{name:string;ip_address?:string;status:string;source_type:string;system_name?:string;system_description?:string};hours:number;samples:GraphSample[];latest?:GraphSample;message?:string};
type MetricKey='cpu_percent'|'memory_percent'|'disk_percent'|'network_receive_bps'|'network_send_bps';

const friendly=(error:unknown)=>error instanceof ApiFailure?error.message:'Unable to load device graphs.';
const rate=(value:number|undefined)=>{if(value===undefined||value===null)return '-';const bits=value*8;if(bits>=1_000_000_000)return `${(bits/1_000_000_000).toFixed(2)} Gbps`;if(bits>=1_000_000)return `${(bits/1_000_000).toFixed(2)} Mbps`;if(bits>=1_000)return `${(bits/1_000).toFixed(1)} Kbps`;return `${bits.toFixed(0)} bps`};
const duration=(seconds:number|undefined)=>{if(seconds===undefined||seconds===null)return '-';const days=Math.floor(seconds/86400),hours=Math.floor(seconds%86400/3600),minutes=Math.floor(seconds%3600/60);return [days&&`${days}d`,hours&&`${hours}h`,`${minutes}m`].filter(Boolean).join(' ')};

function Trend({title,samples,series,percent=false}:{title:string;samples:GraphSample[];series:{key:MetricKey;label:string;color:string}[];percent?:boolean}){
  const all=series.flatMap(item=>samples.map(sample=>sample[item.key]).filter((value):value is number=>typeof value==='number'))
  const ceiling=percent?100:Math.max(...all,1)*1.1
  function points(key:MetricKey){const values=samples.map((sample,index)=>({value:sample[key],x:samples.length===1?0:index*600/(samples.length-1)})).filter(item=>typeof item.value==='number') as {value:number;x:number}[];return values.map(item=>`${item.x.toFixed(1)},${(150-(item.value/ceiling)*140).toFixed(1)}`).join(' ')}
  return <article className="trendCard"><header><strong>{title}</strong><div>{series.map(item=><span key={item.key}><i style={{background:item.color}}/>{item.label}</span>)}</div></header>{all.length?<svg viewBox="0 0 600 160" preserveAspectRatio="none" role="img" aria-label={`${title} history`}><path d="M0 150H600 M0 80H600 M0 10H600"/>{series.map(item=><polyline key={item.key} points={points(item.key)} style={{stroke:item.color}}/>)}</svg>:<p>No reported values for this metric.</p>}</article>
}

export function DeviceGraphs({target,onBack,onExpired}:{target:GraphTarget|null;onBack:()=>void;onExpired:()=>void}){
  const [hours,setHours]=React.useState(24),[data,setData]=React.useState<GraphData|null>(null),[error,setError]=React.useState('')
  const load=React.useCallback(()=>{if(!target)return;api<GraphData>(`/api/v1/graphs/${target.source_type}/${target.id}?hours=${hours}`).then(value=>{setData(value);setError('')}).catch(value=>{if(value instanceof AuthenticationRequired)onExpired();else setError(friendly(value))})},[target,hours,onExpired])
  React.useEffect(()=>{setData(null);void load();const timer=setInterval(()=>void load(),10000);return()=>clearInterval(timer)},[load])
  if(!target)return <section className="panel page graphPage"><div className="panelHead"><div><h3>Device Graphs</h3><p>Open Agents and choose Graphs beside an enrolled Agent or SNMP device.</p></div><button className="secondaryButton" onClick={onBack}>Choose device</button></div></section>
  const latest=data?.latest
  return <section className="panel page graphPage">
    <div className="panelHead"><div><p className="graphBreadcrumb">{target.source_type.toUpperCase()} monitoring</p><h3>{data?.identity.name||target.name}</h3><p>{data?.identity.ip_address||'IP not reported'} ú Actual collected samples only</p></div><div className="graphControls"><select value={hours} onChange={event=>setHours(Number(event.target.value))}><option value={1}>Last hour</option><option value={6}>Last 6 hours</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option></select><button className="secondaryButton" onClick={onBack}>Back</button></div></div>
    {error&&<p role="alert">{error}</p>}
    <section className="graphSummary"><article><span>Status</span><b className={`graphStatus ${data?.identity.status||'unknown'}`}>{data?.identity.status||'Loading'}</b></article><article><span>Uptime</span><b>{duration(latest?.uptime_seconds)}</b></article><article><span>CPU</span><b>{latest?.cpu_percent===undefined?'-':`${latest.cpu_percent.toFixed(1)}%`}</b></article><article><span>RAM</span><b>{latest?.memory_percent===undefined?'-':`${latest.memory_percent.toFixed(1)}%`}</b></article><article><span>Disk</span><b>{latest?.disk_percent===undefined?'-':`${latest.disk_percent.toFixed(1)}%`}</b></article><article><span>Samples</span><b>{data?.samples.length??0}</b></article></section>
    {data?.message&&<div className="graphWaiting">{data.message} Agent history is sampled every 30 seconds; SNMP follows the configured poll interval.</div>}
    <section className="trendGrid">
      <Trend title="Processor" samples={data?.samples||[]} percent series={[{key:'cpu_percent',label:'CPU',color:'#128765'}]}/>
      <Trend title="Memory and disk" samples={data?.samples||[]} percent series={[{key:'memory_percent',label:'RAM',color:'#3979b8'},{key:'disk_percent',label:'Disk',color:'#d17b24'}]}/>
      <Trend title="Network bandwidth" samples={data?.samples||[]} series={[{key:'network_receive_bps',label:'Receive',color:'#128765'},{key:'network_send_bps',label:'Send',color:'#7257b5'}]}/>
    </section>
    <section className="interfacePanel"><div><h3>Interfaces / ports</h3><p>SNMP aliases are shown first, followed by the device interface name.</p></div><div className="tableScroll"><table className="deviceTable"><thead><tr><th>Interface</th><th>Port name</th><th>Status</th><th>Link speed</th><th>Receive</th><th>Send</th></tr></thead><tbody>{latest?.interfaces?.map((item,index)=><tr key={item.index??index}><td>{item.name}</td><td>{item.port_name||item.name}</td><td><span className={`statusBadge ${item.status==='up'?'online':'offline'}`}>{item.status}</span></td><td>{item.speed_bps?rate(item.speed_bps/8):'-'}</td><td>{rate(item.receive_bps)}</td><td>{rate(item.send_bps)}</td></tr>)}</tbody></table>{!latest?.interfaces?.length&&<div className="graphWaiting">No interface data reported yet.</div>}</div></section>
  </section>
}
