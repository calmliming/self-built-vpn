// Match FlClash's capacity labels and 1024-based conversion.
export const CLIENT_GB_BYTES = 1024 ** 3;
export const DEFAULT_QUOTA_BYTES = 500 * CLIENT_GB_BYTES;
export const MAX_QUOTA_BYTES = 9_000_000_000_000_000;

export function bytes(value:number|null):string {
  if(value===null)return '待采集';
  const units=['B','KB','MB','GB','TB','PB'];
  let unit=0;
  while(value>=1024&&unit<units.length-1){value/=1024;unit++}
  return `${new Intl.NumberFormat('zh-CN',{maximumFractionDigits:unit?1:0}).format(value)} ${units[unit]}`;
}

export function quotaAmount(value:number):string {
  const amount=value/CLIENT_GB_BYTES;
  const rounded=Number(amount.toFixed(1));
  return amount>=0.1&&rounded*CLIENT_GB_BYTES<=MAX_QUOTA_BYTES?String(rounded):String(amount);
}

export function quotaBytes(amount:string, unlimited:boolean, originalBytes:number):number|null {
  if(unlimited)return null;
  // An unchanged rounded value must not silently increase/decrease a quota.
  const unchanged=Number(amount)===Number(quotaAmount(originalBytes));
  const total=unchanged?originalBytes:Math.round(Number(amount)*CLIENT_GB_BYTES);
  if(!Number.isSafeInteger(total)||total<=0||total>MAX_QUOTA_BYTES)throw new Error('请输入有效的总额度');
  return total;
}
