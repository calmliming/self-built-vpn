import {useEffect,useState} from 'react';
import {Globe2,LoaderCircle} from 'lucide-react';
import {api} from './api';
import type {Dashboard,Task} from './types';
import {regions} from './types';

export default function ExitPolicy(p:{data:Dashboard;onTask:(task:Task)=>void;reload:()=>void;notify:(message:string,error?:boolean)=>void}) {
  const [choice,setChoice]=useState(p.data.me.exit_region||''),[busy,setBusy]=useState(false);
  useEffect(()=>setChoice(p.data.me.exit_region||''),[p.data.me.exit_region]);
  async function save(){
    setBusy(true);
    try {const task=await api<Task>('/routing/exit','PATCH',{region:choice||null});p.onTask(task);p.reload();}
    catch(e){p.notify(e instanceof Error?e.message:'出口策略未保存',true);}
    finally {setBusy(false);}
  }
  return <section className="glass card" style={{marginBottom:24}}><div className="card-heading"><div><h2>出口地区</h2><p>固定地区后，订阅仅包含该地区节点；Hysteria2 不可用时在同地区切换备用协议。</p></div><Globe2 size={23}/></div>
    <div className="filters"><label className="field">我的出口策略<select aria-label="我的出口策略" value={choice} onChange={e=>setChoice(e.target.value)} disabled={busy}><option value="">按地区顺序自动回退</option>{p.data.me.regions.map(code=><option value={code} key={code}>固定{regions[code]}出口</option>)}</select></label>
      <button className="button primary" disabled={busy||!p.data.me.ready||choice===(p.data.me.exit_region||'')} onClick={save}>{busy&&<LoaderCircle size={16} className="spin"/>}保存并发布订阅</button></div>
    <p className="hint">当前：{p.data.me.exit_region?'固定'+regions[p.data.me.exit_region]+'出口，自动组仅在该地区内回退':'按授权地区自动回退'}。发布完成后刷新客户端订阅。国内和局域网继续直连。</p>
  </section>;
}
