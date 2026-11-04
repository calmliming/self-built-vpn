import { useEffect, useRef, useState, type ReactNode } from 'react';
import { ArrowLeftRight } from 'lucide-react';

export default function ScrollableTable({label,children}:{label:string;children:ReactNode}) {
  const scrollRef=useRef<HTMLDivElement>(null);
  const [overflow,setOverflow]=useState(false);

  useEffect(()=>{
    const container=scrollRef.current;
    if(!container)return;
    const measure=()=>setOverflow(container.scrollWidth>container.clientWidth+1);
    const observer=new ResizeObserver(measure);
    observer.observe(container);
    const table=container.querySelector('table');
    if(table)observer.observe(table);
    measure();
    return()=>observer.disconnect();
  },[]);

  return <div className="table-region">
    {overflow&&<p className="table-hint"><ArrowLeftRight size={14}/>左右滑动或使用方向键查看全部列</p>}
    <div ref={scrollRef} className="table-scroll" role="region" aria-label={label} tabIndex={overflow?0:undefined}>{children}</div>
  </div>;
}
