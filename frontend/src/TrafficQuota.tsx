import { useState, type FormEvent } from 'react';
import { Gauge, LoaderCircle } from 'lucide-react';
import { api } from './api';
import type { Member, Traffic } from './types';
import { Modal, time } from './components';
import { regions } from './types';
import { bytes, CLIENT_GB_BYTES, DEFAULT_QUOTA_BYTES, MAX_QUOTA_BYTES, quotaAmount, quotaBytes } from './trafficFormat';

export function TrafficUsage({traffic:t,compact=false}:{traffic:Traffic;compact?:boolean}) {
  const total=t.total_bytes===null?'不限量':bytes(t.total_bytes);
  const period=t.period==='month'?`${t.month} · 每月重置`:'累计额度';
  const percent=t.total_bytes&&t.used_bytes!==null?Math.min(100,t.used_bytes/t.total_bytes*100):0;
  if(compact)return <div className={'traffic-compact '+(t.exceeded?'exceeded':'')}>
    <span>已用 <strong>{bytes(t.used_bytes)}</strong></span><span>总额度 <strong>{total}</strong></span>
    <small>{t.period==='month'?'本月':'累计'}{t.quota_status==='blocked'?' · 代理已暂停':t.quota_status==='pending'?' · 停复机规则待同步':t.status==='partial'?' · 部分统计待更新':t.status==='pending'?' · 等待采集':''}</small>
  </div>;
  return <div className={'traffic-usage '+(t.exceeded?'exceeded':'')}>
    <div className="traffic-heading"><span><Gauge size={16}/>订阅流量</span><small>{period}</small></div>
    <div className="traffic-facts">
      <div><span>总额度</span><strong>{total}</strong></div>
      <div><span>已使用额度</span><strong>{bytes(t.used_bytes)}</strong></div>
      <div><span>剩余额度</span><strong>{t.total_bytes===null?'不限量':bytes(t.remaining_bytes)}</strong></div>
    </div>
    {t.total_bytes!==null&&<div className="meter" role="progressbar" aria-label="订阅额度使用比例" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(percent)}><i style={{width:percent+'%'}}/></div>}
    <p className="traffic-directions"><span>上传 {bytes(t.upload_bytes)}</span><span>下载 {bytes(t.download_bytes)}</span></p>
    <p className="hint">容量与 FlClash 统一按 1024 换算。后台约每 2 分钟同步；客户端在更新订阅时刷新用量。</p>
    {t.status==='partial'&&<p className="traffic-warning">{t.unavailable_regions.map(r=>regions[r]).join('、')}统计待更新，保留已采集用量。</p>}
    {t.quota_status==='blocked'&&<p className="traffic-warning">{t.quota_reason==='quota-exhausted'?`本期额度已用完，代理已暂停，${t.period==='month'?'下月自动恢复。':'增加额度后自动恢复。'}`:'额度校验暂不可用，代理已暂停，服务恢复后自动重连。'}</p>}
    {t.enforced&&t.total_bytes!==null&&<p className="hint">{t.quota_status==='pending'?'自动停复机规则正在同步。':`用满自动暂停代理${t.period==='month'?' · 北京时间每月 1 日自动恢复':''} · 服务器约每 10 秒检查`}</p>}
    <p className="hint">{t.started_at?`统计始于 ${time(t.started_at)}，更新于 ${time(t.updated_at)}`:'启用统计后显示真实用量；历史流量无法补算。'}</p>
    {t.includes_legacy&&<p className="hint">含原共享订阅用量，共享链接的流量统一计入管理员。</p>}
  </div>;
}

export function QuotaEditor({member,onClose,onSaved}:{member:Member;onClose:()=>void;onSaved:()=>void}) {
  const [unlimited,setUnlimited]=useState(member.traffic.total_bytes===null);
  const [originalBytes]=useState(member.traffic.total_bytes??DEFAULT_QUOTA_BYTES);
  const [amount,setAmount]=useState(quotaAmount(originalBytes));
  const [period,setPeriod]=useState(member.traffic.period);
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  async function submit(event:FormEvent) {
    event.preventDefault();setBusy(true);setError('');
    try {
      const total=quotaBytes(amount,unlimited,originalBytes);
      await api('/members/'+member.id+'/quota','PATCH',{total_bytes:total,period});
      onSaved();
    } catch(error){setError(error instanceof Error?error.message:'保存失败，请重试');setBusy(false)}
  }
  return <Modal title="设置订阅流量额度" description={member.display_name+' · 保存后同步到订阅客户端'} onClose={onClose}>
    <form onSubmit={submit}>
      <div className="modal-body form-stack">
        <TrafficUsage traffic={member.traffic}/>
        <label className="quota-unlimited"><input type="checkbox" checked={unlimited} onChange={e=>setUnlimited(e.target.checked)}/>不限总流量</label>
        {!unlimited&&<label className="field">总额度（GB，与 FlClash 一致）<input type="number" min={1/CLIENT_GB_BYTES} max={MAX_QUOTA_BYTES/CLIENT_GB_BYTES} step="any" required value={amount} onChange={e=>setAmount(e.target.value)}/><small>1 GB 按 1024³ 字节换算</small></label>}
        <label className="field">统计周期<select value={period} onChange={e=>setPeriod(e.target.value as Traffic['period'])}><option value="month">每月 · 北京时间每月 1 日重置</option><option value="lifetime">累计 · 不自动重置</option></select></label>
        <p className="hint">按上传与下载合计，达到额度后自动暂停该成员所有设备的代理。每月额度在北京时间每月 1 日重置并自动恢复。更换订阅链接或凭据不会清零用量；国内直连继续可用。</p>
        {error&&<div className="notice amber" role="alert">{error}</div>}
      </div>
      <footer><button type="button" className="button" onClick={onClose}>取消</button><button className="button primary" disabled={busy}>{busy&&<LoaderCircle size={16} className="spin"/>}保存额度</button></footer>
    </form>
  </Modal>;
}
