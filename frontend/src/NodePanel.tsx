import { useEffect, useState } from 'react';
import { Download, LoaderCircle, Network, Search, ShieldCheck } from 'lucide-react';
import { api } from './api';
import { Badge, Empty, time } from './components';
import type { Dashboard, Node, SpeedSample, SpeedTests, Task } from './types';
import { regions } from './types';

export function SpeedValue({sample}:{sample?:SpeedSample}) {
  if (!sample) return <span className="muted">尚未测速</span>;
  if (sample.mbps === null) return <div className="speed-value"><span className="error-text">未取得速率</span><small>{sample.message}</small><small>{time(sample.tested_at)}</small></div>;
  return <div className="speed-value"><strong>{sample.mbps.toFixed(2)} <span>Mbps</span></strong>
    <small>{(sample.mbps / 8).toFixed(2)} MB/s · {(sample.bytes / 1e6).toFixed(2)} MB / {sample.seconds?.toFixed(2)} 秒</small>
    <small>{sample.status === 'sampled' ? '限时采样' : '完整下载'} · {time(sample.tested_at)}</small></div>;
}

export default function NodePanel(p:{data:Dashboard;onTask:(task:Task)=>void;notify:(message:string,error?:boolean)=>void;reload:()=>void}) {
  const [nodes,setNodes]=useState<Node[]|null>(null),[speeds,setSpeeds]=useState<SpeedTests|null>(null);
  const [region,setRegion]=useState('all'),[protocol,setProtocol]=useState('all'),[search,setSearch]=useState('');
  const [error,setError]=useState(''),[submitting,setSubmitting]=useState(false),[reloadKey,setReloadKey]=useState(0);
  useEffect(()=>{
    let alive=true,loading=false;
    const load=async()=>{
      if(loading)return;
      loading=true;
      try {
        const [inventory,measurements]=await Promise.all([api<Node[]>('/nodes'),api<SpeedTests>('/speed-tests')]);
        if(alive){setNodes(inventory);setSpeeds(measurements);setError('');}
      } catch(e) {if(alive)setError(e instanceof Error?e.message:'读取测速结果失败');}
      finally {loading=false;}
    };
    void load();const timer=setInterval(load,4000);
    return()=>{alive=false;clearInterval(timer);};
  },[p.data.me.revision,reloadKey]);
  const rows=nodes?.filter(n=>(region==='all'||n.server_id===region)&&(protocol==='all'||n.type===protocol)&&(n.name+n.server).toLowerCase().includes(search.toLowerCase()));
  const count=nodes?.filter(n=>region==='all'||n.server_id===region).length||0;
  const samples=new Map(speeds?.samples.map(s=>[s.server_id+':'+s.node_name,s]));
  const active=speeds?.active;
  async function start(){
    setSubmitting(true);
    try {
      const task=await api<Task>('/speed-tests','POST',{region});
      setSpeeds(old=>old?{...old,active:task}:old);setReloadKey(v=>v+1);p.reload();
      p.notify('下载测速已开始，结果会逐个显示');
    } catch(e) {p.notify(e instanceof Error?e.message:'测速未启动',true);}
    finally {setSubmitting(false);}
  }
  return <section className="glass card">
    <div className="card-heading"><div><h2>协议入口</h2><p>自动组优先 Hysteria2，其他协议作为备用</p></div>
      <span className="protocol blue-text"><ShieldCheck size={14}/> Hysteria2 优先</span></div>
    <div className="speed-toolbar"><div><strong>实际下载测速</strong>
      <p>从{speeds?.source||'管理后台所在设备'}经节点下载 Cloudflare 测试文件，结果反映当前网络。</p>
      <small>按地区测试全部协议；每节点最多 {((speeds?.payload_bytes||3000000)/1e6).toFixed(0)} MB / {speeds?.timeout_seconds||12} 秒，本次最多 {count*((speeds?.payload_bytes||3000000)/1e6)} MB。</small>
    </div><button className="button primary" disabled={submitting||!!active||!count||!p.data.me.ready} onClick={start}>
      {submitting||active?<LoaderCircle size={16} className="spin"/>:<Download size={16}/>}
      {active?'测速进行中':submitting?'正在启动':'测速'+(region==='all'?'全部地区':regions[region])}</button></div>
    {active&&<div className="notice speed-progress" role="status"><LoaderCircle className="spin" size={16}/><span>{active.details.at(-1)?.message||'测速任务正在排队'} · 已取得 {active.details.filter(e=>e.speed).length} 项结果</span><button className="button ghost" onClick={()=>p.onTask(active)}>查看进度</button></div>}
    <div className="filters"><div className="pills">{['all',...p.data.me.regions].map(r=><button className={region===r?'active':''} onClick={()=>setRegion(r)} key={r}>{r==='all'?'全部地区':regions[r]}</button>)}</div>
      <label className="search"><Search size={16}/><input placeholder="搜索节点或 IP" value={search} onChange={e=>setSearch(e.target.value)}/></label>
      <select aria-label="筛选协议" value={protocol} onChange={e=>setProtocol(e.target.value)}><option value="all">全部协议</option>{['vless','trojan','hysteria2','http','socks5'].map(t=><option key={t} value={t}>{t.toUpperCase()}</option>)}</select></div>
    {error&&<div className="notice amber">{error}</div>}
    {!nodes?<div className="loading"><LoaderCircle size={25} className="spin"/>正在读取节点与测速结果</div>:<div className="table-scroll"><table><thead><tr><th>节点名称</th><th>地区</th><th>协议</th><th>地址与端口</th><th>实际下载</th><th>服务器状态</th></tr></thead><tbody>{rows?.map(n=><tr key={n.server+':'+n.port}>
      <td><span className="node-name"><Network size={17}/><strong>{n.name}</strong></span></td><td>{regions[n.server_id]}</td>
      <td><span className={'protocol '+(n.type==='hysteria2'?'blue-text':'')}>{n.type==='vless'?'VLESS · REALITY':n.type.toUpperCase()}</span><small>{n.transport} · TLS 验证开启{n.type==='hysteria2'?' · 自动优先':''}</small></td>
      <td className="mono">{n.server}:{n.port}</td><td><SpeedValue sample={samples.get(n.server_id+':'+n.name)}/></td><td><Badge state={n.health}/></td>
    </tr>)}</tbody></table>{!rows?.length&&<Empty>没有符合条件的节点</Empty>}</div>}
    <p className="hint speed-footnote">Mbps 为平均下载速率；限时采样按已接收数据计算。单次小文件测速不能代表长期带宽，不会自动改动你的客户端选择。</p>
  </section>;
}
