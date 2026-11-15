import {arcSampler,visibleRoutes} from "./routeGeometry";
import {useEffect,useRef,useState} from "react";
import {geoOrthographic,geoPath,geoGraticule10,geoRotation} from "d3-geo";
import {feature,mesh} from "topojson-client";
import world from "world-atlas/countries-110m.json";
import {hasCoordinates,routeColor} from "./data";
const land=feature(world,world.objects.countries), borders=mesh(world,world.objects.countries,(a,b)=>a!==b);
const RAD=Math.PI/180;
export default function Globe({routes,origin,selected,onSelect,rotate,setRotate}) {
 const canvas=useRef(null), view=useRef({rotation:[50,-20,0],zoom:1}), props=useRef(), drag=useRef(null), hits=useRef([]);
 const [hover,setHover]=useState(null);
 props.current={routes:routes.map(r=>({...r,sample:arcSampler({...r,observedOrigin:r.observedOrigin||origin})})),origin,selected,onSelect,rotate};
 useEffect(()=>{
  const el=canvas.current,ctx=el.getContext("2d");if(!ctx)return;
  let frame,old=performance.now(),last=0,width=0,height=0;
  const reduced=matchMedia("(prefers-reduced-motion: reduce)").matches;
  const resize=new ResizeObserver(([entry])=>{width=entry.contentRect.width;height=entry.contentRect.height;el.width=width*Math.min(devicePixelRatio,2);el.height=height*Math.min(devicePixelRatio,2);});
  resize.observe(el);
  function draw(time){
   frame=requestAnimationFrame(draw);if(time-last<32)return;last=time;
   const dt=Math.min(time-old,80);old=time;
   if(!width || !height)return;
   const current=props.current,v=view.current;
   if(current.rotate && !drag.current && !reduced)v.rotation[0]+=dt*.0025;
   const radius=Math.min(width*.39,height*.405)*v.zoom,cx=width/2,cy=height/2;
   const dpr=Math.min(devicePixelRatio,2);ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,width,height);
   const projection=geoOrthographic().translate([cx,cy]).scale(radius).rotate(v.rotation).clipAngle(90);
   const path=geoPath(projection,ctx),rotation=geoRotation(v.rotation);
   const project=(coord,elevation=1)=>{
    const [lng,lat]=rotation(coord).map(a=>a*RAD);
    const z=Math.cos(lat)*Math.cos(lng);
    return {x:cx+radius*elevation*Math.cos(lat)*Math.sin(lng),y:cy-radius*elevation*Math.sin(lat),z,visible:z>=0 || elevation*Math.sqrt(1-z*z)>1.003};
   };
   const halo=ctx.createRadialGradient(cx,cy,radius*.85,cx,cy,radius*1.35);halo.addColorStop(0,"#9abdc80b");halo.addColorStop(1,"#9abdc800");ctx.fillStyle=halo;ctx.fillRect(0,0,width,height);
   ctx.strokeStyle="#ffffff0c";ctx.lineWidth=1;
   for(const scale of [1.09,1.19]){ctx.beginPath();ctx.arc(cx,cy,radius*scale,0,2*Math.PI);ctx.stroke();}
   ctx.beginPath();path({type:"Sphere"});ctx.fillStyle="#0b1014";ctx.fill();ctx.strokeStyle="#f3f6f75e";ctx.lineWidth=1;ctx.stroke();
   ctx.beginPath();path(geoGraticule10());ctx.strokeStyle="#d4e1e512";ctx.lineWidth=.55;ctx.stroke();
   ctx.beginPath();path(land);ctx.fillStyle="#d5e2e506";ctx.fill();ctx.strokeStyle="#f2f4f7a6";ctx.lineWidth=.8;ctx.stroke();
   ctx.beginPath();path(borders);ctx.strokeStyle="#ffffff7c";ctx.lineWidth=.55;ctx.stroke();
   hits.current=[];
   function dot(p,color,size=2.5){if(p.z<0)return;ctx.save();ctx.shadowBlur=14;ctx.shadowColor=color;ctx.fillStyle=color;ctx.beginPath();ctx.arc(p.x,p.y,size,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;ctx.strokeStyle=color+"50";ctx.beginPath();ctx.arc(p.x,p.y,size+5,0,Math.PI*2);ctx.stroke();ctx.restore();}
   const plotted=visibleRoutes(current.routes,current.selected);
   // Draw the selected connection last so it remains legible.
   plotted.sort((a,b)=>Number(a.id===current.selected)-Number(b.id===current.selected));
   for(const route of plotted){
    const home=route.observedOrigin || current.origin;
    if(!hasCoordinates(home) || !hasCoordinates(route))continue;
    const sample=route.sample;
    const color=routeColor(route),isSelected=route.id===current.selected;
    const points=Array.from({length:65},(_,i)=>{const t=i/64;const p=sample(t);return project(p.coord,p.elevation);});
    ctx.save();ctx.strokeStyle=color;ctx.lineWidth=isSelected?2:1.15;ctx.globalAlpha=current.selected&&!isSelected?.3:.75;ctx.shadowBlur=isSelected?12:5;ctx.shadowColor=color;ctx.beginPath();
    for(let i=1;i<points.length-1;i++){const p=points[i];if(p.visible)hits.current.push({x:p.x,y:p.y,route});}
    let pen=false;for(const p of points){if(!p.visible){pen=false;continue;}if(!pen)ctx.moveTo(p.x,p.y);else ctx.lineTo(p.x,p.y);pen=true;}ctx.stroke();
    if(!reduced){const t=((time/6500)+(route.remote_port||0)%7/7)%1;const sampled=sample(t),p=project(sampled.coord,sampled.elevation);if(p.visible){ctx.fillStyle="#fff";ctx.beginPath();ctx.arc(p.x,p.y,isSelected?2.3:1.5,0,Math.PI*2);ctx.fill();}}
    if(route.kind==="incident"){const start=project([home.lng,home.lat]);dot(start,color,isSelected?3.6:2.2);if(start.z>=0)hits.current.push({x:start.x,y:start.y,route});}
    const dest=project([route.lng,route.lat]);dot(dest,color,isSelected?3.6:2.2);
    if(dest.z>=0)hits.current.push({x:dest.x,y:dest.y,route});
    ctx.restore();
   }
   if(hasCoordinates(current.origin)){const home=project([current.origin.lng,current.origin.lat]);dot(home,"#ffffff",4);if(home.z>=0){ctx.fillStyle="#e1e9ec";ctx.font="10px monospace";ctx.fillText("YOUR DEVICE",home.x+13,home.y-10);}}
  }
  frame=requestAnimationFrame(draw);return()=>{cancelAnimationFrame(frame);resize.disconnect();};
 },[]);
 useEffect(()=>{const route=routes.find(r=>r.id===selected);if(hasCoordinates(route)){view.current.rotation=[-route.lng,-route.lat,0];}},[selected]);
 const point=e=>{const rect=canvas.current.getBoundingClientRect();return [e.clientX-rect.left,e.clientY-rect.top];};
 const move=e=>{
  if(drag.current){const d=drag.current;const dx=e.clientX-d.x,dy=e.clientY-d.y;if(Math.abs(dx)+Math.abs(dy)>3)d.moved=true;view.current.rotation=[d.rotation[0]+dx*.3,Math.max(-85,Math.min(85,d.rotation[1]-dy*.3)),0];return;}
  const [x,y]=point(e),hit=hits.current.find(h=>Math.hypot(h.x-x,h.y-y)<12);setHover(hit?{x,y,route:hit.route}:null);
 };
 return <div className="globe-wrap">
  <canvas ref={canvas} tabIndex={0} role="img" aria-label="Interactive globe of approximate connection locations. Drag or use arrow keys to rotate. Plus and minus zoom. Select a connection from the list for accessible details."
   onPointerDown={e=>{drag.current={x:e.clientX,y:e.clientY,rotation:[...view.current.rotation],moved:false};canvas.current.setPointerCapture(e.pointerId);setRotate(false);setHover(null);}}
   onPointerMove={move} onPointerUp={e=>{if(drag.current&&!drag.current.moved){const [x,y]=point(e),hit=hits.current.find(h=>Math.hypot(h.x-x,h.y-y)<12);if(hit)onSelect(hit.route.id);}drag.current=null;}}
   onPointerCancel={()=>{drag.current=null;}} onPointerLeave={()=>setHover(null)}
   onKeyDown={e=>{if(["ArrowLeft","ArrowRight","ArrowUp","ArrowDown","+","=","-"].includes(e.key)){e.preventDefault();setRotate(false);if(e.key.startsWith("Arrow")){view.current.rotation[0]+=(e.key==="ArrowRight"?8:e.key==="ArrowLeft"?-8:0);view.current.rotation[1]=Math.max(-85,Math.min(85,view.current.rotation[1]+(e.key==="ArrowUp"?8:e.key==="ArrowDown"?-8:0)));}else view.current.zoom=Math.max(.65,Math.min(1.45,view.current.zoom+(e.key==="-"?-.1:.1)));}}}/>
  {hover&&<div className="globe-tooltip" style={{left:Math.min(hover.x+12,canvas.current.clientWidth-200),top:hover.y-44}}><strong>{hover.route.kind==="incident"?hover.route.severity+" incident":hover.route.country_name||"Unknown location"}</strong><span>{hover.route.kind==="incident"?hover.route.ip:hover.route.process_name}</span></div>}
  <div className="globe-controls"><button aria-label="Zoom in" onClick={()=>view.current.zoom=Math.min(1.45,view.current.zoom+.1)}>+</button><button aria-label="Zoom out" onClick={()=>view.current.zoom=Math.max(.65,view.current.zoom-.1)}>−</button><span/><button className={rotate?"active":""} aria-pressed={rotate} onClick={()=>setRotate(!rotate)}>↻ <span>Rotate</span></button><button aria-label="Reset globe view" onClick={()=>{view.current={rotation:[50,-20,0],zoom:1};onSelect(null);}}>⌖</button></div>
  <div className="globe-instruction">DRAG TO EXPLORE <span>·</span> SELECT A CONNECTION TO FOCUS</div>
 </div>;
}
