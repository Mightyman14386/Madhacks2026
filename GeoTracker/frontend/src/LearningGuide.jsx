import {useState} from "react";
const lessons={
 basics:{label:"What am I seeing?",title:"A connection is a conversation between computers.",text:"Apps contact other computers to load pages, sync files, or check for updates. A connection alone does not mean something is wrong.",tip:"Start by selecting a row. Look for an app or description you recognize."},
 privacy:{label:"What data is shared?",title:"This view shows connections, not their contents.",text:"An IP address is a network address. It helps identify an endpoint, but it does not reveal which messages, passwords, or files were sent.",tip:"Use the app's permissions and privacy settings to understand what it can access. This dashboard cannot inspect the contents of an encrypted connection."},
 risk:{label:"Should I worry?",title:"Treat a finding as a reason to investigate.",text:"Severity is a priority label, not proof of an attack. An unfamiliar country or cloud provider is not automatically dangerous.",tip:"Check the app name, description, and reported reasons together before taking action."}
};
export default function LearningGuide({incident=false,item,mode,stale=false}){
 const [topic,setTopic]=useState("basics"),[open,setOpen]=useState(false);
 const lesson=lessons[topic];
 const backendDescription=typeof item?.description==="string"?item.description.trim():"";
 const description=backendDescription|| (item?(incident
  ?"This record links a reported source location to a destination. Its "+(item.severity||"unknown")+" severity comes from the database; it is not an independent assessment of your device."
  :(item.process_name||"This app")+" contacted a remote endpoint. "+(item.status==="unsafe"?"Local rules flagged this connection for review. Read the reasons below before deciding what to do.":"No alert is shown for this connection. That does not guarantee that the app or destination is trustworthy."))
  :incident?"These are reported incidents from a database, not a live capture of your device. Updates refresh the records; they do not reveal the contents of anyone's traffic."
  :"This view checks which apps have network connections. It helps you spot unfamiliar activity, but it cannot tell you exactly which files or messages an app sent.");
 return <section className="learning-guide" aria-label="Security learning guide">
  <div className="learning-summary"><div className="learning-mark" aria-hidden="true">?</div><div className="learning-copy"><div className="learning-kicker">YOUR SECURITY COMPANION <span>Local explanations</span></div><h2>{item?"This activity, explained":"Understand what you see"}</h2><p>{description}</p>{stale&&<p className="learning-status">You are looking at the last received snapshot while updates reconnect.</p>}</div><button className="learning-toggle" aria-expanded={open} onClick={()=>setOpen(!open)}>{open?"Close guide":"Help me understand"} <span aria-hidden="true">{open?"−":"+"}</span></button></div>
  {open&&<div className="learning-expanded"><div className="learning-topics" aria-label="Learning topics">{Object.entries(lessons).map(([key,value])=><button key={key} aria-pressed={topic===key} onClick={()=>setTopic(key)}>{value.label}</button>)}</div><div className="learning-lesson"><div><h3>{lesson.title}</h3><p>{lesson.text}</p></div><aside><span>TRY THIS</span><p>{lesson.tip}</p></aside></div>{!incident&&<p className="learning-mode">{mode==="Enforcing"?"Enforcement is enabled: security actions can affect real processes or files.":mode==="Dry-run"?"Dry run means enforcement is disabled. Observing real connections and enforcing protection are separate.":mode==="Preview only"?"These examples are simulated so you can explore the interface.":"The backend has not confirmed the protection mode yet."}</p>}<p className="learning-footnote">Based on the displayed record and local guidance. No AI model is connected; no data is sent to an AI service.</p></div>}
 </section>;
}
