const terms=[
 [/\bDNS\b/i,"DNS","The service that translates a website name into a network address."],
 [/\bHTTPS?\b|\bTLS\b|\bSSL\b/i,"Web connection","HTTPS and TLS encrypt data in transit. Encryption alone does not establish whether a destination is trustworthy."],
 [/\bexfiltrat(?:ion|e|ed)\b/i,"Exfiltration","A term for data being transferred out without authorization. Here, this is a claim in the record, not something this dashboard independently verified."],
 [/\bphishing\b/i,"Phishing","An attempt to trick someone into sharing information or opening a malicious link."],
 [/\bmalware\b|\bbotnet\b/i,"Malicious software","Software that may act without the owner's permission. Read the reported evidence before assuming a specific app is infected."],
 [/\bIP\b/i,"IP address","A network address for an endpoint. It does not identify a person or show the contents of a transfer."],
 [/\bport\b/i,"Port","A number used to direct a connection to a service on a computer."],
 [/\bfirewall\b/i,"Firewall","A control that allows or blocks network connections according to rules."]
];
export default function ConnectionExplanation({item}){
 if(!item)return null;
 const description=typeof item.description==="string"&&item.description.trim()?item.description.trim():(item.reasons||[]).filter(r=>typeof r==="string").join(" ");
 const matched=terms.filter(([pattern])=>pattern.test(description)).slice(0,3);
 return <section className="connection-explanation" aria-label="Selected connection explanation" aria-live="polite">
  <div className="explanation-label">CONNECTION EXPLAINED <span>From backend data</span></div>
  <h3>{item.ip||item.remote_ip||item.process_name||"Selected connection"}</h3>
  <p className="explanation-description">{description||"The backend did not provide a description or findings for this connection."}</p>
  {!!matched.length&&<dl>{matched.map(([,name,text])=><div key={name}><dt>{name}</dt><dd>{text}</dd></div>)}</dl>}
  <p className="explanation-context">{description?"This is what the backend reports for the connection you selected. It does not show the actual contents of the traffic.":"There is not enough information to explain why this connection occurred."}</p>
 </section>;
}
