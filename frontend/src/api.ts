let csrf = '';
export function setCSRF(value:string) { csrf = value; }
export class ApiError extends Error { constructor(message:string, public status:number) { super(message); } }
export async function api<T>(path:string, method='GET', body?:unknown):Promise<T> {
  const response = await fetch('/api'+path, {method, credentials:'same-origin', headers:{'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':csrf}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
  const result = await response.json().catch(()=>({detail:'服务响应异常'}));
  if (!response.ok) throw new ApiError(typeof result.detail==='string'?result.detail:'输入格式有误，请检查填写内容',response.status);
  return result as T;
}
export async function copy(value:string) {
  await navigator.clipboard.writeText(value);
}
