import {useEffect,useRef,useState} from "react";
export default function usePoll(fn,interval,enabled,onData) {
 const callback=useRef(onData);callback.current=onData;
 const [error,setError]=useState(null),[loading,setLoading]=useState(true);
 useEffect(()=>{
  if(!enabled){setLoading(false);return;}
  let stopped=false,timer;const controller=new AbortController();setLoading(true);
  async function run(){try {const data=await fn(controller.signal);if(!stopped){callback.current(data);setError(null);}}catch(e){if(!stopped && e.name!=="AbortError")setError(e.message);}finally{if(!stopped){setLoading(false);timer=setTimeout(run,interval);}}}
  timer=setTimeout(run,0);return()=>{stopped=true;controller.abort();clearTimeout(timer);};
 },[fn,interval,enabled]);
 return {error,loading};
}
